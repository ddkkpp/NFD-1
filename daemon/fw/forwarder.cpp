/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2021,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "forwarder.hpp"  

#include "algorithm.hpp"
#include "best-route-strategy.hpp"
#include "scope-prefix.hpp"
#include "strategy.hpp"
#include "common/global.hpp"
#include "common/logger.hpp"
#include "table/cleanup.hpp"

#include <ndn-cxx/lp/pit-token.hpp>
#include <ndn-cxx/lp/tags.hpp>

#include "face/null-face.hpp"
#include <deque>
#include <thread>

namespace nfd {

NFD_LOG_INIT(Forwarder);

const std::string CFG_FORWARDER = "forwarder";

static Name
getDefaultStrategyName()
{
  return fw::BestRouteStrategy::getStrategyName();
}

Forwarder::Forwarder(FaceTable& faceTable)
  : m_faceTable(faceTable)
  , m_unsolicitedDataPolicy(make_unique<fw::DefaultUnsolicitedDataPolicy>())
  , m_fib(m_nameTree)
  , m_pit(m_nameTree)
  , m_measurements(m_nameTree)
  , m_strategyChoice(*this)
  , m_csFace(face::makeNullFace(FaceUri("contentstore://")))
{
  m_faceTable.addReserved(m_csFace, face::FACEID_CONTENT_STORE);

  m_faceTable.afterAdd.connect([this] (const Face& face) {
    face.afterReceiveInterest.connect(
      [this, &face] (const Interest& interest, const EndpointId& endpointId) {
        this->onIncomingInterest(interest, FaceEndpoint(const_cast<Face&>(face), endpointId));
      });
    face.afterReceiveData.connect(
      [this, &face] (const Data& data, const EndpointId& endpointId) {
        this->onIncomingData(data, FaceEndpoint(const_cast<Face&>(face), endpointId));
      });
    face.afterReceiveNack.connect(
      [this, &face] (const lp::Nack& nack, const EndpointId& endpointId) {
        this->onIncomingNack(nack, FaceEndpoint(const_cast<Face&>(face), endpointId));
      });
    face.onDroppedInterest.connect(
      [this, &face] (const Interest& interest) {
        this->onDroppedInterest(interest, const_cast<Face&>(face));
      });
  });

  m_faceTable.beforeRemove.connect([this] (const Face& face) {
    cleanupOnFaceRemoval(m_nameTree, m_fib, m_pit, face);
  });

  m_fib.afterNewNextHop.connect([this] (const Name& prefix, const fib::NextHop& nextHop) {
    this->onNewNextHop(prefix, nextHop);
  });

  m_strategyChoice.setDefaultStrategy(getDefaultStrategyName());
}

Forwarder::~Forwarder() = default;

void
Forwarder::probe(const Interest& interest, const FaceEndpoint& ingress){
  NFD_LOG_DEBUG("start probing");
  auto it = face_info.find(const_cast<FaceEndpoint&>(ingress));
  //由于F分布临界值没有直接的函数实现，所以之后直接使用预计算的恶意临界值（10个包中，恶意包为0或1则判定为诚实），这里的nSendTotalProbe如果改变后，后面的判定恶意的代码也要改变
  for(auto i=it->cachedContentName.rbegin();i!=it->cachedContentName.rend();i++)
  {
    if(*i!=interest.getName())
    {
    shared_ptr<Name> nameWithSequence = make_shared<Name>(*i);
    shared_ptr<Interest> probe = make_shared<Interest>();
    uint32_t nonce=rand()%(std::numeric_limits<uint32_t>::max()-1);
    probe->setNonce(nonce);
    NFD_LOG_DEBUG("set nouce");
    probe->setName(*nameWithSequence);
    NFD_LOG_DEBUG("probe is"<<probe->getName());
    
    ingress.face.sendInterest(*probe);
    auto seq=probe->getName().get(1).toSequenceNumber();
    probeFilter.Add(seq,0);//记录probe的name
    NFD_LOG_DEBUG("add to probefilter: "<<seq);
    }
  }
  // for(size_t i=0;i<nSendTotalProbe;i++){
  //   NFD_LOG_DEBUG("enter for");
  //   shared_ptr<Name> nameWithSequence = make_shared<Name>(interest.getName().getPrefix(1));//前缀必须是已经注册过的，不然兴趣包没有转发路径
  //   nameWithSequence->append("probe");
  //   int seq=rand();
  //   NFD_LOG_DEBUG("setSeq: "<<seq);
  //   nameWithSequence->appendSequenceNumber(seq);
  //   NFD_LOG_DEBUG("constucted name");
  //   shared_ptr<Interest> probe = make_shared<Interest>();
  //   NFD_LOG_DEBUG("声明probe");
  //   uint32_t nonce=rand()%(std::numeric_limits<uint32_t>::max()-1);
  //   probe->setNonce(nonce);
  //   //probe->setNonce(m_rand->GetValue(0, std::numeric_limits<uint32_t>::max()-1));//不知道为什么运行到这里就崩溃了
  //   NFD_LOG_DEBUG("set nouce");
  //   probe->setName(*nameWithSequence);
  //   NFD_LOG_DEBUG("set name");
  //   //probe->setCanBeServedByCS(false);
  //   NFD_LOG_DEBUG("probe is"<<probe->getName());
  //   NFD_LOG_DEBUG("readSeq: "<<probe->getName().get(2).toSequenceNumber());
  //   // for(auto it =face_ei.left.begin();it!=face_ei.left.end();++it){
  //   //   it->first->face.sendInterest(*probe, it->first->endpoint);
  //   //   // it->first.face.sendInterest(*probe, it->first.endpoint);
  //   ingress.face.sendInterest(*probe);
  //   probeFilter.Add(seq,0);//记录probe的name
  //   NFD_LOG_DEBUG("add to probefilter: "<<seq);
  //   // for(auto it =face_info.begin();it!=face_info.end();++it){
  //   //   it->face.sendInterest(*probe, it->endpoint);
  //   //   NFD_LOG_DEBUG("sendProbe to " << *it << " , probe=" << probe->getName());
  //   //   // NFD_LOG_DEBUG("subname: "<<probe->getName().getSubName(1,1));
  //   //   // NFD_LOG_DEBUG("stoi: "<<stoi(probe->getName().getSubName(1,1).toUri()));
  //   //   // probeFilter.Add(atoi(nameWithSequence->toUri().c_str()),0);//记录probe的name
  //   //   probeFilter.Add(seq,0);//记录probe的name
  //   //   NFD_LOG_DEBUG("add to probefilter: "<<seq);
  //   // }
  // }
}

void
Forwarder::onIncomingInterest(const Interest& interest, const FaceEndpoint& ingress)
{
  //如果是反馈包
  if(interest.getNonce()==std::numeric_limits<uint32_t>::max())
  {
    NFD_LOG_DEBUG("onIncomingFeedback in=" << ingress << " feedback=" << interest.getName());
    // auto content=interest.getApplicationParameters();
    // //content的buffer是vector<uint8_t>,遍历该容器，转化为过滤器能使用的uint64_t
    // uint64_t content_64=0;
    // int j=0;
    // for(auto i=content.value_begin();i<content.value_end();i++){
    // if(j==7){
    //   j=0;
    // }
    // content_64+=((*i)<<(8*j));//用*i
    // j++;
    // }
    //interest.setTag(make_shared<lp::FeedbackDataTag>(0));
    if(interest.getTag<lp::FeedbackDataTag>()==nullptr){
      NFD_LOG_DEBUG("getTag = nullptr");
    }
    auto content_64=*(interest.getTag<lp::FeedbackDataTag>());
    //uint64_t content=interest.getContentinFeedback();
    NFD_LOG_DEBUG("Feedback aims at malicious content is : "<<content_64);
    uint32_t ei=0;
    //feedback携带的data是否在过滤器中
    if(dataFilter.Contain(content_64, ei) == cuckoofilter::Ok){
    // if(dataFilter.Contain(content, ei) == cuckoofilter::Ok){
      NFD_LOG_DEBUG("feedback's content is in dataFilter, so Feedback is real");
      //方案中此处有对content签名的验证，实验上画图时只考虑用户诚实的方案开销，所以此处省略。
      //若考虑用户恶意，此处只需加上验证的延时（在转发策略sleep或schedule不会影响测量的延时，可以把延时加在app上）
      NFD_LOG_DEBUG("ei= "<<ei);
      auto it=face_ei.right.find(ei);
      auto face_in_set=face_info.find(it->second);
      FaceEndpoint temp=*face_in_set;
      //auto target_face=it->second;
      //将反馈转发出去
       NFD_LOG_DEBUG(*face_in_set<<" is target_face");
      // NFD_LOG_DEBUG(*target_face<<" is target_face");
      if(finishProbing&&!face_in_set->isMalicious){//结束探测才转发反馈，否则保存反馈
        NFD_LOG_DEBUG("此时探测已经结束，可以转发反馈");
        face_in_set->face.sendInterest(interest);
      }
      else{
        NFD_LOG_DEBUG("此时探测未结束，不能转发反馈");
        //laterFbFace=face_in_set->face;
        laterFeedback.push_back(interest);
      }

      // target_face->face.sendInterest(interest, target_face->endpoint);
      //删除污染缓存，删除最大数量暂定为5，可能有风险
      // m_cs.erase(interest.getName(),5,bind(&Forwarder::onCsErase, this))   
      m_cs.erase(interest.getName(),5,[=] (size_t nErased){}) ;
      //删除储存的邻居缓存中反馈的名字
      //temp.cachedContentName.erase(interest.getName());
      NFD_LOG_DEBUG("forward feedback to target_face: "<<*face_in_set);
      //NFD_LOG_DEBUG("forward feedback to target_face: "<<*target_face);
      if((!face_in_set->isTarget)&&(!face_in_set->isMalicious)){
        NFD_LOG_DEBUG("mark "<<*face_in_set<<" as target_face");
        temp.isTarget=true;
        face_info.erase(*face_in_set);
        face_info.insert(temp);
        // face_ei.right.replace_data(it, target_face);
        // it=face_ei.right.find(ei);
        NFD_LOG_DEBUG("after mark target: "<<face_info.find(it->second)->isTarget);
        isProbing=true;
        //开始探测

        probe(interest,temp);
      }
      // if((!target_face->isTarget)&&(!target_face->isMalicious)){
      //   NFD_LOG_DEBUG("mark "<<*target_face<<" as target_face");
      //   target_face->isTarget=true;
      //   NFD_LOG_DEBUG("after mark target: "<<target_face->isTarget);
      //   NFD_LOG_DEBUG("after mark target: "<<it->second->isTarget);
      //   face_ei.right.replace_data(it, target_face);
      //   it=face_ei.right.find(ei);
      //   NFD_LOG_DEBUG("after mark target: "<<it->second->isTarget);
      //   isProbing=true;
      //   //开始探测
      //   probe(interest);
      // }   
    return;   
    }
    // return;   
  }

  // receive Interest
  NFD_LOG_DEBUG("onIncomingInterest in=" << ingress << " interest=" << interest.getName());
  interest.setTag(make_shared<lp::IncomingFaceIdTag>(ingress.face.getId()));
  ++m_counters.nInInterests;

  // drop if HopLimit zero, decrement otherwise (if present)
  if (interest.getHopLimit()) {
    if (*interest.getHopLimit() == 0) {
      NFD_LOG_DEBUG("onIncomingInterest in=" << ingress << " interest=" << interest.getName()
                    << " hop-limit=0");
      ++ingress.face.getCounters().nInHopLimitZero;
      // drop
      return;
    }
    const_cast<Interest&>(interest).setHopLimit(*interest.getHopLimit() - 1);
  }

  // /localhost scope control
  bool isViolatingLocalhost = ingress.face.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(interest.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onIncomingInterest in=" << ingress
                  << " interest=" << interest.getName() << " violates /localhost");
    // drop
    return;
  }

  // detect duplicate Nonce with Dead Nonce List
  bool hasDuplicateNonceInDnl = m_deadNonceList.has(interest.getName(), interest.getNonce());
  if (hasDuplicateNonceInDnl) {
    // goto Interest loop pipeline
    this->onInterestLoop(interest, ingress);
    return;
  }

  // strip forwarding hint if Interest has reached producer region
  if (!interest.getForwardingHint().empty() &&
      m_networkRegionTable.isInProducerRegion(interest.getForwardingHint())) {
    NFD_LOG_DEBUG("onIncomingInterest in=" << ingress
                  << " interest=" << interest.getName() << " reaching-producer-region");
    const_cast<Interest&>(interest).setForwardingHint({});
  }

  // PIT insert
  shared_ptr<pit::Entry> pitEntry = m_pit.insert(interest).first;

  // detect duplicate Nonce in PIT entry
  int dnw = fw::findDuplicateNonce(*pitEntry, interest.getNonce(), ingress.face);
  bool hasDuplicateNonceInPit = dnw != fw::DUPLICATE_NONCE_NONE;
  if (ingress.face.getLinkType() == ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    // for p2p face: duplicate Nonce from same incoming face is not loop
    hasDuplicateNonceInPit = hasDuplicateNonceInPit && !(dnw & fw::DUPLICATE_NONCE_IN_SAME);
  }
  if (hasDuplicateNonceInPit) {
    // goto Interest loop pipeline
    this->onInterestLoop(interest, ingress);
    m_strategyChoice.findEffectiveStrategy(*pitEntry).afterReceiveLoopedInterest(ingress, interest, *pitEntry);
    return;
  }

  // // CanBeServedByCS(自己加的，目的：探测包不应该用CS满足)
  // if(!interest.getCanBeServedByCS()){
  //   this->onContentStoreMiss(ingress, pitEntry, interest);
  // }
  //is pending?
  if (!pitEntry->hasInRecords()) {
    NFD_LOG_DEBUG("没有PIT");
    m_cs.find(interest,
              [=] (const Interest& i, const Data& d) { onContentStoreHit(i, ingress, pitEntry, d); },
              [=] (const Interest& i) { onContentStoreMiss(i, ingress, pitEntry); });
  }
  else {
    NFD_LOG_DEBUG("有PIT");
    this->onContentStoreMiss(interest, ingress, pitEntry);
  }
}

void
Forwarder::onInterestLoop(const Interest& interest, const FaceEndpoint& ingress)
{
  // if multi-access or ad hoc face, drop
  if (ingress.face.getLinkType() != ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    NFD_LOG_DEBUG("onInterestLoop in=" << ingress
                  << " interest=" << interest.getName() << " drop");
    return;
  }

  NFD_LOG_DEBUG("onInterestLoop in=" << ingress << " interest=" << interest.getName()
                << " send-Nack-duplicate");

  // send Nack with reason=DUPLICATE
  // note: Don't enter outgoing Nack pipeline because it needs an in-record.
  lp::Nack nack(interest);
  nack.setReason(lp::NackReason::DUPLICATE);
  ingress.face.sendNack(nack);
}

void
Forwarder::onContentStoreMiss(const Interest& interest, const FaceEndpoint& ingress,
                              const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG("onContentStoreMiss interest=" << interest.getName());
  ++m_counters.nCsMisses;
  afterCsMiss(interest);

  // attach HopLimit if configured and not present in Interest
  if (m_config.defaultHopLimit > 0 && !interest.getHopLimit()) {
    const_cast<Interest&>(interest).setHopLimit(m_config.defaultHopLimit);
  }

  // insert in-record
  pitEntry->insertOrUpdateInRecord(ingress.face, interest);

  // set PIT expiry timer to the time that the last PIT in-record expires
  auto lastExpiring = std::max_element(pitEntry->in_begin(), pitEntry->in_end(),
                                       [] (const auto& a, const auto& b) {
                                         return a.getExpiry() < b.getExpiry();
                                       });
  auto lastExpiryFromNow = lastExpiring->getExpiry() - time::steady_clock::now();
  this->setExpiryTimer(pitEntry, time::duration_cast<time::milliseconds>(lastExpiryFromNow));

  // has NextHopFaceId?
  auto nextHopTag = interest.getTag<lp::NextHopFaceIdTag>();
  if (nextHopTag != nullptr) {
    // chosen NextHop face exists?
    Face* nextHopFace = m_faceTable.get(*nextHopTag);
    if (nextHopFace != nullptr) {
      NFD_LOG_DEBUG("onContentStoreMiss interest=" << interest.getName()
                    << " nexthop-faceid=" << nextHopFace->getId());
      // go to outgoing Interest pipeline
      // scope control is unnecessary, because privileged app explicitly wants to forward
      this->onOutgoingInterest(interest, *nextHopFace, pitEntry);
    }
    return;
  }

  // dispatch to strategy: after receive Interest
  m_strategyChoice.findEffectiveStrategy(*pitEntry)
    .afterReceiveInterest(interest, FaceEndpoint(ingress.face, 0), pitEntry);
}

void
Forwarder::onContentStoreHit(const Interest& interest, const FaceEndpoint& ingress,
                             const shared_ptr<pit::Entry>& pitEntry, const Data& data)
{
  NFD_LOG_DEBUG("onContentStoreHit interest=" << interest.getName());
  ++m_counters.nCsHits;
  afterCsHit(interest, data);

  data.setTag(make_shared<lp::IncomingFaceIdTag>(face::FACEID_CONTENT_STORE));
  data.setTag(interest.getTag<lp::PitToken>());
  // FIXME Should we lookup PIT for other Interests that also match the data?

  pitEntry->isSatisfied = true;
  pitEntry->dataFreshnessPeriod = data.getFreshnessPeriod();

  // set PIT expiry timer to now
  this->setExpiryTimer(pitEntry, 0_ms);

  beforeSatisfyInterest(*pitEntry, *m_csFace, data);
  m_strategyChoice.findEffectiveStrategy(*pitEntry).beforeSatisfyInterest(data, FaceEndpoint(*m_csFace, 0), pitEntry);

  // dispatch to strategy: after Content Store hit
  m_strategyChoice.findEffectiveStrategy(*pitEntry).afterContentStoreHit(data, ingress, pitEntry);
}

pit::OutRecord*
Forwarder::onOutgoingInterest(const Interest& interest, Face& egress,
                              const shared_ptr<pit::Entry>& pitEntry)
{
  // drop if HopLimit == 0 but sending on non-local face
  if (interest.getHopLimit() == 0 && egress.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL) {
    NFD_LOG_DEBUG("onOutgoingInterest out=" << egress.getId() << " interest=" << pitEntry->getName()
                  << " non-local hop-limit=0");
    ++egress.getCounters().nOutHopLimitZero;
    return nullptr;
  }

  NFD_LOG_DEBUG("onOutgoingInterest out=" << egress.getId() << " interest=" << pitEntry->getName());

  // insert out-record
  auto it = pitEntry->insertOrUpdateOutRecord(egress, interest);
  BOOST_ASSERT(it != pitEntry->out_end());

  // send Interest
  egress.sendInterest(interest);
  ++m_counters.nOutInterests;
  return &*it;
}

void
Forwarder::onInterestFinalize(const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG("onInterestFinalize interest=" << pitEntry->getName()
                << (pitEntry->isSatisfied ? " satisfied" : " unsatisfied"));

  if (!pitEntry->isSatisfied) {
    beforeExpirePendingInterest(*pitEntry);
  }

  // Dead Nonce List insert if necessary
  this->insertDeadNonceList(*pitEntry, nullptr);

  // Increment satisfied/unsatisfied Interests counter
  if (pitEntry->isSatisfied) {
    ++m_counters.nSatisfiedInterests;
  }
  else {
    ++m_counters.nUnsatisfiedInterests;
  }

  // PIT delete
  pitEntry->expiryTimer.cancel();
  m_pit.erase(pitEntry.get());
}

void
Forwarder::onIncomingData(const Data& data, const FaceEndpoint& ingress)
{  
  //std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // auto it = face_ei.left.find(ingress);
  // if(it!=face_ei.left.end())
  // {
  //   // FaceEndpoint fep=it->first;
  //   FaceEndpoint fep=it->first;
  //   //收到数据来自已经确定是恶意的端口，直接丢弃
  //   if(fep.isMalicious){
  //     NFD_LOG_DEBUG("Receive data from malicious FaceEndpoint " << fep<<", drop it");
  //     return;
  //   }
  //   //收到数据是探测数据包,计数后丢弃
  //   uint32_t ei=0;
  //   if(data.getName().size()>2)
  //   {
  //     if(probeFilter.Contain(data.getName().get(2).toSequenceNumber(),ei)==cuckoofilter::Ok)
  //     {
  //       NFD_LOG_DEBUG("dataname is in probefilter: "<<data.getName()<<", seq: "<<data.getName().get(2).toSequenceNumber());
  //       if(!isProbing){//探测结束
  //         return;
  //       }
  //       NFD_LOG_DEBUG("Receive ProbeData in=" << ingress << " data=" << data.getName());

  //       //数据为假
  //       if(::ndn::readNonNegativeInteger(data.getSignature().getValue())==std::numeric_limits<uint32_t>::max()){
  //         NFD_LOG_DEBUG("nReceiveInvalidProbeData in " << ingress<<" before is "<<fep.nReceiveInvalidProbeData);
  //         fep.nReceiveInvalidProbeData+=1;
  //         face_ei.left.replace_key(it, fep);
  //         //++((face_ei.left.find(const_cast<FaceEndpoint*>(&ingress)))->first->nReceiveInvalidProbeData);
  //         //ingress.nReceiveInvalidProbeData+=1;
  //         NFD_LOG_DEBUG("ProbeData is invalid" << " data=" << data.getName());
  //         NFD_LOG_DEBUG("nReceiveInvalidProbeData in " << ingress<<" ++, now is "<<fep.nReceiveInvalidProbeData);
  //       }
  //       else{
  //         NFD_LOG_DEBUG("ProbeData is valid" << " data=" << data.getName());
  //       }
  //       fep.nReceiveTotalProbeData+=1;
  //       face_ei.left.replace_key(it, fep);
  //       //++(face_ei.left.find(const_cast<FaceEndpoint*>(&ingress))->first->nReceiveTotalProbeData);
  //       //判断当前端口是否受到足够探测包
  //       if(fep.nReceiveTotalProbeData>=
  //               (fep.rateofReceivetoSend)*
  //               (fep.nSendTotalProbe)){
  //         fep.receiveEnoughProbe=true;
  //         face_ei.left.replace_key(it, fep);
  //         NFD_LOG_DEBUG("Receive enough ProbeData in=" << ingress<<", faceid is "<< ingress.face.getId());
  //       }
  //       //判断所有端口是否收到足够探测包
  //       for(auto it =face_ei.left.begin();it!=face_ei.left.end();++it){
  //           if(!it->first.receiveEnoughProbe){
  //             allFaceReceiveEnoughProbe=false;
  //             break;
  //           }
  //       }
  //       //判断targetFace是否是恶意端口,目前支持一个端口是否恶意的判断
  //       if(allFaceReceiveEnoughProbe){
  //         NFD_LOG_DEBUG("Receive enough ProbeData in all interfaces");
  //         double targetFaceMal;
  //         double totalMal,avgMal,accum,stdev;
  //         auto targetinBimap=it;//记录bimap中targetFace处的迭代器
  //         auto targetFace=it->first;
  //         for(it =face_ei.left.begin();it!=face_ei.left.end();++it){
  //           if(it->first.isTarget){
  //             targetinBimap=it;
  //             targetFace=it->first;
  //             targetFaceMal=(it->first.nReceiveInvalidProbeData)/(it->first.nReceiveTotalProbeData);
  //             NFD_LOG_DEBUG("targetFace is " << targetFace<<", targetFaceMal is "<<targetFaceMal);
  //             continue;
  //           }
  //           totalMal+=(it->first.nReceiveInvalidProbeData)/(it->first.nReceiveTotalProbeData);
  //         }
  //         avgMal=totalMal/(face_ei.size()-1);  
  //         NFD_LOG_DEBUG("avgMal=" << avgMal);
  //         for(it =face_ei.left.begin();it!=face_ei.left.end();++it){
  //           if(it->first.isTarget){
  //             continue;
  //           }
  //           accum+=pow(((it->first.nReceiveInvalidProbeData) / (it->first.nReceiveTotalProbeData-avgMal)) , 2);
  //         }
  //         stdev=sqrt(accum/(face_ei.size()-1));  
  //         if(targetFaceMal<(avgMal-3*stdev)){
  //           targetFace.isMalicious=true;
  //           NFD_LOG_DEBUG("targetface " <<targetFace<< " is malicious");
  //         }
  //         else{
  //           NFD_LOG_DEBUG("targetface " <<targetFace<< " is honest");
  //         }
  //         targetFace.isTarget=false;
  //         face_ei.left.replace_key(targetinBimap, targetFace);
  //         isProbing=false;
  //         for(auto it =face_ei.left.begin();it!=face_ei.left.end();++it){
  //             fep=it->first;
  //             fep.nReceiveInvalidProbeData=0;
  //             fep.nReceiveTotalProbeData=0;
  //             fep.receiveEnoughProbe=false;
  //             face_ei.left.replace_key(it,fep);
  //         }
  //       }
  //       return;
  //     }
  //   }
  //   //端口正在探测且是普通数据包：直接丢弃
  //   else if(ingress.isTarget){
  //     NFD_LOG_DEBUG("Receive non-probe data from targetFace: " <<ingress << ", faceid is "<< ingress.face.getId()<<" , drop it");
  //     return;
  //   }
  // }
  auto it = face_info.find(const_cast<FaceEndpoint&>(ingress));
  if(it!=face_info.end())
  {
    // FaceEndpoint fep=it->first;
    //shared_ptr<FaceEndpoint> fep=it->first;
    FaceEndpoint temp=*it;
    FaceEndpoint temp_old=*it;
    //收到数据来自已经确定是恶意的端口，直接丢弃
    if(it->isMalicious){
      NFD_LOG_DEBUG("Receive data from malicious FaceEndpoint " << *it<<", drop it");
      return;
    }
    //收到数据是探测数据包,计数
    uint32_t ei=0;
    // if(data.getName().size()>2)
    // {
      if(probeFilter.Contain(data.getName().get(1).toSequenceNumber(),ei)==cuckoofilter::Ok)
      {
        NFD_LOG_DEBUG("dataname is in probefilter: "<<data.getName()<<", seq: "<<data.getName().get(1).toSequenceNumber());
        if(!isProbing){//探测结束
          return;
        }
        NFD_LOG_DEBUG("Receive ProbeData in=" << ingress << " data=" << data.getName());

        //数据为假
        // if(::ndn::readNonNegativeInteger(data.getSignature().getValue())==std::numeric_limits<uint32_t>::max()){
        NFD_LOG_DEBUG("signature = "<<data.getSignatureInfo().getSignatureType());
        if(data.getSignatureInfo().getSignatureType()==1){
          temp.nReceiveInvalidProbeData+=1;
          //fep->nReceiveInvalidProbeData+=1;
          //face_ei.left.replace_key(it, fep);
          //++((face_ei.left.find(const_cast<FaceEndpoint*>(&ingress)))->first->nReceiveInvalidProbeData);
          //ingress.nReceiveInvalidProbeData+=1;
          NFD_LOG_DEBUG("ProbeData is invalid" << " data=" << data.getName());
          //NFD_LOG_DEBUG("nReceiveInvalidProbeData in " << ingress<<" ++, now is "<<fep->nReceiveInvalidProbeData);
        }
        else{
          NFD_LOG_DEBUG("ProbeData is valid" << " data=" << data.getName());
        }
        NFD_LOG_DEBUG("nReceiveInvalidProbeData in " << ingress<<" is "<<temp.nReceiveInvalidProbeData);
        temp.nReceiveTotalProbeData+=1;
        face_info.erase(*it);
        face_info.insert(temp);
        //ep->nReceiveTotalProbeData+=1;
        //face_ei.left.replace_key(it, fep);
        //++(face_ei.left.find(const_cast<FaceEndpoint*>(&ingress))->first->nReceiveTotalProbeData);
        //判断当前端口是否受到足够探测包
        NFD_LOG_DEBUG("temp.nReceiveTotalProbeData="<<temp.nReceiveTotalProbeData<<
                      " temp.nSendTotalProbe="<<temp.nSendTotalProbe);
        it = face_info.find(const_cast<FaceEndpoint&>(ingress));
        //收到超过1个假包，则表明恶意
        if(temp.nReceiveInvalidProbeData>1)
        {
          temp.isMalicious=true;
          NFD_LOG_DEBUG("targetface " <<temp<< " is malicious");
          isProbing=false;
          temp.nReceiveInvalidProbeData=0;
          temp.nReceiveTotalProbeData=0;
          temp.receiveEnoughProbe=false;
          face_info.erase(*it);
          face_info.insert(temp);
          finishProbing=true;

          auto& e =const_cast<fib::Entry&>(m_fib.findLongestPrefixMatch(data.getName()));//必须是引用类型，否则报错use of deleted function ‘nfd::fib::Entry::Entry(const nfd::fib::Entry&)
          NFD_LOG_DEBUG("除去fib的恶意端口 entry.prefix() = "<<e.getPrefix());
          // e.removeNextHop(ingress.face);
          m_fib.removeNextHop(e, ingress.face);
          //如果本节点就是恶意，则上游节点都是诚实且缓存都是真的，不必转发反馈以清除缓存和开启探测
          // for(auto i=laterFeedback.begin();i!=laterFeedback.end();i++){
          //   ingress.face.sendInterest(*i);
          // }
        }
        //收到所有探测包后，还没收到超过一个假包，说明诚实
        else if(temp.nReceiveTotalProbeData==temp.nSendTotalProbe)
        {
          //temp.receiveEnoughProbe=true;
          //face_ei.left.replace_key(it, fep);
          NFD_LOG_DEBUG("Receive enough ProbeData in=" << ingress);
        
        
          NFD_LOG_DEBUG("now nReceiveInvalidProbeData="<<face_info.find(const_cast<FaceEndpoint&>(ingress))->nReceiveInvalidProbeData<<
                      "now nReceiveTotalProbeData="<<face_info.find(const_cast<FaceEndpoint&>(ingress))->nReceiveTotalProbeData);
        // //判断所有端口是否收到足够探测包
        // allFaceReceiveEnoughProbe=true;
        // for(auto it =face_info.begin();it!=face_info.end();++it){
        //     if(!it->receiveEnoughProbe){
        //       allFaceReceiveEnoughProbe=false;
        //       NFD_LOG_DEBUG(*it<<".receiveEnoughProbe is false");
        //       break;
        //     }
        // }
        //判断targetFace是否是恶意端口
        //由于F分布临界值没有直接的函数实现，所以这里直接使用预计算的恶意临界值（10个包中，恶意包为0或1则判定为诚实）

          NFD_LOG_DEBUG("targetface " <<temp<< " is honest");
 
          //temp.isTarget=false;正在探测和探测结束，都不再对反馈作出开始探测的反应
          isProbing=false;
          temp.nReceiveInvalidProbeData=0;
          temp.nReceiveTotalProbeData=0;
          temp.receiveEnoughProbe=false;
          face_info.erase(*it);
          face_info.insert(temp);
          
          finishProbing=true;
          //探测完成后再转发反馈
          for(auto i=laterFeedback.begin();i!=laterFeedback.end();i++){
            ingress.face.sendInterest(*i);
          }
        }
        // if(allFaceReceiveEnoughProbe){
        //   NFD_LOG_DEBUG("Receive enough ProbeData in all interfaces");
        //   double targetFaceMal;
        //   double totalMal,avgMal,accum,stdev;
        //   for(it =face_info.begin();it!=face_info.end();++it){
        //     if(it->isTarget){
        //       temp=*it;
        //       temp_old=*it;
        //       targetFaceMal=(it->nReceiveInvalidProbeData)/(it->nReceiveTotalProbeData);
        //       NFD_LOG_DEBUG("targetFace is " << *it<<", targetFaceMal is "<<targetFaceMal);
        //       continue;
        //     }
        //     totalMal+=(it->nReceiveInvalidProbeData)/(it->nReceiveTotalProbeData);
        //   }
        //   avgMal=totalMal/(face_ei.size()-1);  
        //   NFD_LOG_DEBUG("avgMal=" << avgMal);
        //   for(it =face_info.begin();it!=face_info.end();++it){
        //     if(it->isTarget){
        //       continue;
        //     }
        //     accum+=pow(((it->nReceiveInvalidProbeData) / (it->nReceiveTotalProbeData-avgMal)) , 2);
        //   }
        //   stdev=sqrt(accum/(face_ei.size()-1));  
        //   if(targetFaceMal<(avgMal-3*stdev)){
        //     temp.isMalicious=true;
        //     NFD_LOG_DEBUG("targetface " <<temp<< " is malicious");
        //   }
        //   else{
        //     NFD_LOG_DEBUG("targetface " <<temp<< " is honest");
        //   }
        //   temp.isTarget=false;
        //   //face_ei.left.replace_key(targetinBimap, targetFace);
        //   face_info.erase(temp_old);
        //   face_info.insert(temp);
        //   isProbing=false;
        //   for(auto it =face_info.begin();it!=face_info.end();++it){
        //       temp=*it;
        //       temp.nReceiveInvalidProbeData=0;
        //       temp.nReceiveTotalProbeData=0;
        //       temp.receiveEnoughProbe=false;
        //       face_info.erase(*it);
        //       face_info.insert(temp);
        //       //face_ei.left.replace_key(it,fep);
        //   }
        // }
        // allFaceReceiveEnoughProbe=false;

        //return;
      // }
    }
    //端口正在探测且是普通数据包：直接丢弃
    else if(ingress.isTarget){
      NFD_LOG_DEBUG("Receive non-probe data from targetFace: " <<ingress << ", faceid is "<< ingress.face.getId()<<" , drop it");
      return;
    }
  }

  // receive Data
  NFD_LOG_DEBUG("onIncomingData in=" << ingress << " data=" << data.getName());
  data.setTag(make_shared<lp::IncomingFaceIdTag>(ingress.face.getId()));
  ++m_counters.nInData;

  // /localhost scope control
  bool isViolatingLocalhost = ingress.face.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(data.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onIncomingData in=" << ingress << " data=" << data.getName() << " violates /localhost");
    // drop
    return;
  }

  // PIT match
  pit::DataMatchResult pitMatches = m_pit.findAllDataMatches(data);
  if (pitMatches.size() == 0) {
    // goto Data unsolicited pipeline
    this->onDataUnsolicited(data, ingress);
    return;
  }

  // CS insert
  m_cs.insert(data);

  //保存邻居缓存内容的名字
  it = face_info.find(const_cast<FaceEndpoint&>(ingress));
  if(it!=face_info.end())
  {
    FaceEndpoint temp=*it;
    if(temp.cachedContentName.size()==deque_capacity){
      temp.cachedContentName.pop_front();
    }
    temp.cachedContentName.push_back(data.getName());
    face_info.erase(*it);
    face_info.insert(temp);
  }

//此处实现将data插入布谷鸟过滤器
  uint64_t content_64=0;//加入过滤器的元素
  int j=0;
  //content的buffer是vector<uint8_t>,遍历该容器，转化为过滤器能使用的uint64_t
  for(auto i=data.getContent().value_begin();i<data.getContent().value_end();i++){
    if(j==7){
      j=0;
    }
    //std::cout<<"j="<<j<<" i="<<(int)i<<std::endl;
    content_64+=((*i)<<(8*j));
    j++;
    //std::cout<<"content= "<<content<<std::endl;
  }
  j=0;
  NFD_LOG_DEBUG("insert to data_filter: data= "<<content_64);
  //uint64_t face_id = ingress.face.getId();
  //由于过滤器的额外信息只使用4bit，所以不能直接使用face_id, 我们让ei_now从0开始递增，
  //将<ingress,ei_code>键值对插入bimap，键重复或者值重复都会导致插入失败，所以bimap的存储中不会出现不同的相同的端口对应不同的ei_code
  if(ingress.face.getId()!=1){//faceID为1的是内部face
    if(face_ei.size()>0){
    // NFD_LOG_DEBUG("插入前查询ei=0"<<face_ei.right.find(0)->second);
    NFD_LOG_DEBUG("插入前查询ei=0"<<face_ei.right.find(0)->second);
    //face_ei.right.find(0)->second->face.sendData(data, face_ei.right.find(0)->second->endpoint);//仅测试
    
    }
    
    auto a= face_ei.left.insert(std::make_pair(const_cast<FaceEndpoint&>(ingress),ei_now));
    face_info.insert(const_cast<FaceEndpoint&>(ingress));
    uint32_t ei_code=face_ei.left.find(ingress)->second;
    NFD_LOG_DEBUG("insert to face_ei: faceEndpoint=" << ingress
                  << " ei_code=" << ei_code);
    NFD_LOG_DEBUG("插入后查询"<<face_ei.right.find(ei_code)->second);
    // auto a= face_ei.left.insert(std::make_pair(make_shared<FaceEndpoint>(const_cast<FaceEndpoint&>(ingress)),ei_now));
    // auto a= face_ei.left.insert(std::make_pair(&ingress),ei_now);
    // uint32_t ei_code=face_ei.left.find(&ingress)->second;
    // NFD_LOG_DEBUG("insert to face_ei: faceEndpoint=" << ingress
    //               << " ei_code=" << ei_code);
    // NFD_LOG_DEBUG("插入后查询"<<*(face_ei.right.find(ei_now)->second));
    dataFilter.Add(content_64, ei_code);
    if(a.second){//插入bimap成功 
      NFD_LOG_DEBUG("insert bimap succeeds");
      ei_now++;
      NFD_LOG_DEBUG("ei_now"<<ei_now);
    }
  }

  std::set<std::pair<Face*, EndpointId>> satisfiedDownstreams;
  std::multimap<std::pair<Face*, EndpointId>, std::shared_ptr<pit::Entry>> unsatisfiedPitEntries;

  for (const auto& pitEntry : pitMatches) {
    NFD_LOG_DEBUG("onIncomingData matching=" << pitEntry->getName());

    // invoke PIT satisfy callback
    beforeSatisfyInterest(*pitEntry, ingress.face, data);

    std::set<std::pair<Face*, EndpointId>> unsatisfiedDownstreams;
    m_isHonest=m_strategyChoice.findEffectiveStrategy(*pitEntry).satisfyInterest(pitEntry, ingress, data,
                                                                      satisfiedDownstreams, unsatisfiedDownstreams);
    for (const auto& endpoint : unsatisfiedDownstreams) {
      unsatisfiedPitEntries.emplace(endpoint, pitEntry);
    }

    if (unsatisfiedDownstreams.empty()) {
      // set PIT expiry timer to now
      this->setExpiryTimer(pitEntry, 0_ms);

      // mark PIT satisfied
      pitEntry->isSatisfied = true;
    }

    // Dead Nonce List insert if necessary (for out-record of inFace)
    this->insertDeadNonceList(*pitEntry, &ingress.face);

    pitEntry->dataFreshnessPeriod = data.getFreshnessPeriod();

    // clear PIT entry's in and out records
    for (const auto& endpoint : satisfiedDownstreams) {
      pitEntry->deleteInRecord(*endpoint.first);
    }
    pitEntry->deleteOutRecord(ingress.face);
  }

  // now check all unsatisfied entries against to be satisfied downstreams, in case there is
  // intersect, and those PIT entries will be actually satisfied regardless strategy's choice
  for (const auto& unsatisfied : unsatisfiedPitEntries) {
    auto downstreamIt = satisfiedDownstreams.find(unsatisfied.first);
    if (downstreamIt != satisfiedDownstreams.end()) {
      auto pitEntry = unsatisfied.second;
      pitEntry->deleteInRecord(*unsatisfied.first.first);

      if (pitEntry->getInRecords().empty()) { // if nothing left, "closing down" the entry
        // set PIT expiry timer to now
        this->setExpiryTimer(pitEntry, 0_ms);

        // mark PIT satisfied
        pitEntry->isSatisfied = true;
      }
    }
  }

  shared_ptr<Data> data1 = make_shared<Data>(const_cast<Data&>(data));
  if(!m_isHonest)
  {
    shared_ptr<ndn::SignatureInfo> signatureInfo1 = make_shared<ndn::SignatureInfo>(const_cast<ndn::SignatureInfo&>(data.getSignatureInfo()));
    signatureInfo1->setSignatureType(static_cast< ::ndn::tlv::SignatureTypeValue>(1));//1表示假包

    data1->setSignatureInfo(*signatureInfo1);
    NFD_LOG_DEBUG("modify signature maliciously, data=" << data.getName());
    NFD_LOG_DEBUG("SignatureType = "<<data1->getSignatureInfo().getSignatureType());
  }
  
  // foreach pending downstream
  for (const auto& downstream : satisfiedDownstreams) {
    if (downstream.first->getId() == ingress.face.getId() &&
        downstream.second == ingress.endpoint &&
        downstream.first->getLinkType() != ndn::nfd::LINK_TYPE_AD_HOC) {
      continue;
    }
    this->onOutgoingData(*data1, *downstream.first);
  //     bool (*p)(const ndn::Data&,  nfd::face::Face&)=this;
  // ns3::Simulator::Schedule(ns3::Seconds(1),p, *data1, *downstream.first);
//   nfd::face::Face& fe = *downstream.first;
//ns3::Simulator::Schedule(ns3::Seconds(1),&nfd::Forwarder::onOutgoingData, this, *data1, *downstream.first);
    //ns3::Simulator::Schedule(ns3::Seconds(1), [this,data1,downstream]{this->onOutgoingData(*data1,*downstream.first);},*data1,*downstream.first);
  }
}

void
Forwarder::onDataUnsolicited(const Data& data, const FaceEndpoint& ingress)
{
  // accept to cache?
  auto decision = m_unsolicitedDataPolicy->decide(ingress.face, data);
  if (decision == fw::UnsolicitedDataDecision::CACHE) {
    // CS insert
    m_cs.insert(data, true);
  }

  NFD_LOG_DEBUG("onDataUnsolicited in=" << ingress << " data=" << data.getName()
                << " decision=" << decision);
  ++m_counters.nUnsolicitedData;
}

bool
Forwarder::onOutgoingData(const Data& data, Face& egress)
{
  if (egress.getId() == face::INVALID_FACEID) {
    NFD_LOG_WARN("onOutgoingData out=(invalid) data=" << data.getName());
    return false;
  }
  NFD_LOG_DEBUG("onOutgoingData out=" << egress.getId() << " data=" << data.getName());

  // /localhost scope control
  bool isViolatingLocalhost = egress.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(data.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onOutgoingData out=" << egress.getId() << " data=" << data.getName()
                  << " violates /localhost");
    // drop
    return false;
  }

  // TODO traffic manager

  // send Data

  //1. make-event.h:426:59: error: ‘((ns3::MakeEvent(MEM, OBJ, T1) [with MEM = nfd::Forwarder::onOutgoingData(const ndn::Data&, nfd::face::Face&)::<lambda()>; 
  //OBJ = nfd::Forwarder*; T1 = ndn::Data]::EventMemberImpl1*)this)->ns3::MakeEvent(MEM, OBJ, T1) [with MEM = nfd::Forwarder::onOutgoingData(const ndn::Data&, nfd::face::Face&)::<lambda()>; 
  //OBJ = nfd::Forwarder*; T1 = ndn::Data]::EventMemberImpl1::m_function’ cannot be used as a member pointer, since it is of type ‘nfd::Forwarder::onOutgoingData(const ndn::Data&, nfd::face::Face&)::<lambda()>’
  //2./usr/include/c++/9/ext/new_allocator.h:146:4: error: use of deleted function ‘nfd::face::Face::Face(const nfd::face::Face&)
  // auto face1=make_shared<Face>(const_cast<Face&>(egress));
  // auto lamda=[face1,data](){face1->sendData(data);};
  // ns3::Simulator::Schedule(ns3::Seconds(1),lamda, this, data);

  //1.make-event.h:396:52: error: incomplete type ‘ns3::EventMemberImplObjTraits<ndn::Data>’ used in nested name specifier
  //2.usr/include/c++/9/ext/new_allocator.h:146:4: error: use of deleted function ‘nfd::face::Face::Face(const nfd::face::Face&)
  // auto face1=make_shared<Face>(const_cast<Face&>(egress));
  // auto lamda=[face1,data](){face1->sendData(data);};
  // ns3::Simulator::Schedule(ns3::Seconds(1),lamda, data);

  //forwarder.cpp:953:27: error: invalid use of non-static member function ‘void nfd::face::Face::sendData(const ndn::Data&)’
  // auto b=std::bind(egress.sendData, data);

  // auto face1=make_shared<Face>(const_cast<Face&>(egress));
  // auto b=std::bind(face1->sendData, data);
  // ns3::Simulator::Schedule(ns3::Seconds(1),b, data);

  //make-event.h:396:52: error: incomplete type ‘ns3::EventMemberImplObjTraits<ndn::Data>’ used in nested name specifier
  // std::function<void()> fooBar = [egress,&data]() { egress.sendData(data); };
  // std::function<void()> fooBar = [&]() { egress.sendData(data); };
  // ns3::Simulator::Schedule(ns3::Seconds(1),fooBar, data);

  //1.forwarder.cpp:961:72: error: passing ‘const nfd::face::Face’ as ‘this’ argument discards qualifiers [-fpermissive]
  //2. error: use of deleted function ‘nfd::face::Face::Face(const nfd::face::Face&)’
  // std::function<void()> fooBar = [egress,data]() { egress.sendData(data); };


  //forwarder.cpp:954:14: error: use of deleted function ‘nfd::face::Face::Face(const nfd::face::Face&)
  // auto lamda=[egress,data](){const_cast<Face&>(egress).sendData(data);};

  //forwarder.cpp:954:50: error: passing ‘const nfd::face::Face’ as ‘this’ argument discards qualifiers 
  //auto lamda=[egress,data](){const_cast<Face&>(egress).sendData(data);};


  //make-event.h:396:52: error: incomplete type ‘ns3::EventMemberImplObjTraits<ndn::Data>’ used in nested name specifier(大概是嵌套名称标识符中，未声明就使用的意思)
  // void (nfd::face::Face::*p)(const ndn::Data&)=&nfd::face::Face::sendData;
  // ns3::Simulator::Schedule(ns3::Seconds(1), p, data);

  //ns3::Simulator::Schedule(ns3::Seconds(1), nfd::face::Face::sendData, data);

  //make-event.h:426:59: error: pointer to member type ‘void (nfd::face::Face::)(const ndn::Data&)’ incompatible with object type ‘nfd::Forwarder’
  // void (nfd::face::Face::*p)(const ndn::Data&)=&nfd::face::Face::sendData;
  // ns3::Simulator::Schedule(ns3::Seconds(1), p, this, data);

  egress.sendData(data);
  ++m_counters.nOutData;

  return true;
}

void
Forwarder::onIncomingNack(const lp::Nack& nack, const FaceEndpoint& ingress)
{
  // receive Nack
  nack.setTag(make_shared<lp::IncomingFaceIdTag>(ingress.face.getId()));
  ++m_counters.nInNacks;

  // if multi-access or ad hoc face, drop
  if (ingress.face.getLinkType() != ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    NFD_LOG_DEBUG("onIncomingNack in=" << ingress
                  << " nack=" << nack.getInterest().getName() << "~" << nack.getReason()
                  << " link-type=" << ingress.face.getLinkType());
    return;
  }

  // PIT match
  shared_ptr<pit::Entry> pitEntry = m_pit.find(nack.getInterest());
  // if no PIT entry found, drop
  if (pitEntry == nullptr) {
    NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()
                  << "~" << nack.getReason() << " no-PIT-entry");
    return;
  }

  // has out-record?
  auto outRecord = pitEntry->getOutRecord(ingress.face);
  // if no out-record found, drop
  if (outRecord == pitEntry->out_end()) {
    NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()
                  << "~" << nack.getReason() << " no-out-record");
    return;
  }

  // if out-record has different Nonce, drop
  if (nack.getInterest().getNonce() != outRecord->getLastNonce()) {
    NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()
                  << "~" << nack.getReason() << " wrong-Nonce " << nack.getInterest().getNonce()
                  << "!=" << outRecord->getLastNonce());
    return;
  }

  NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()
                << "~" << nack.getReason() << " OK");

  // record Nack on out-record
  outRecord->setIncomingNack(nack);

  // set PIT expiry timer to now when all out-record receive Nack
  if (!fw::hasPendingOutRecords(*pitEntry)) {
    this->setExpiryTimer(pitEntry, 0_ms);
  }

  // trigger strategy: after receive NACK
  m_strategyChoice.findEffectiveStrategy(*pitEntry).afterReceiveNack(nack, ingress, pitEntry);
}

bool
Forwarder::onOutgoingNack(const lp::NackHeader& nack, Face& egress,
                          const shared_ptr<pit::Entry>& pitEntry)
{
  if (egress.getId() == face::INVALID_FACEID) {
    NFD_LOG_WARN("onOutgoingNack out=(invalid)"
                 << " nack=" << pitEntry->getInterest().getName() << "~" << nack.getReason());
    return false;
  }

  // has in-record?
  auto inRecord = pitEntry->getInRecord(egress);

  // if no in-record found, drop
  if (inRecord == pitEntry->in_end()) {
    NFD_LOG_DEBUG("onOutgoingNack out=" << egress.getId()
                  << " nack=" << pitEntry->getInterest().getName()
                  << "~" << nack.getReason() << " no-in-record");
    return false;
  }

  // if multi-access or ad hoc face, drop
  if (egress.getLinkType() != ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    NFD_LOG_DEBUG("onOutgoingNack out=" << egress.getId()
                  << " nack=" << pitEntry->getInterest().getName() << "~" << nack.getReason()
                  << " link-type=" << egress.getLinkType());
    return false;
  }

  NFD_LOG_DEBUG("onOutgoingNack out=" << egress.getId()
                << " nack=" << pitEntry->getInterest().getName()
                << "~" << nack.getReason() << " OK");

  // create Nack packet with the Interest from in-record
  lp::Nack nackPkt(inRecord->getInterest());
  nackPkt.setHeader(nack);

  // erase in-record
  pitEntry->deleteInRecord(egress);

  // send Nack on face
  egress.sendNack(nackPkt);
  ++m_counters.nOutNacks;

  return true;
}

void
Forwarder::onDroppedInterest(const Interest& interest, Face& egress)
{
  m_strategyChoice.findEffectiveStrategy(interest.getName()).onDroppedInterest(interest, egress);
}

void
Forwarder::onNewNextHop(const Name& prefix, const fib::NextHop& nextHop)
{
  const auto affectedEntries = this->getNameTree().partialEnumerate(prefix,
    [&] (const name_tree::Entry& nte) -> std::pair<bool, bool> {
      // we ignore an NTE and skip visiting its descendants if that NTE has an
      // associated FIB entry (1st condition), since in that case the new nexthop
      // won't affect any PIT entries anywhere in that subtree, *unless* this is
      // the initial NTE from which the enumeration started (2nd condition), which
      // must always be considered
      if (nte.getFibEntry() != nullptr && nte.getName().size() > prefix.size()) {
        return {false, false};
      }
      return {nte.hasPitEntries(), true};
    });

  for (const auto& nte : affectedEntries) {
    for (const auto& pitEntry : nte.getPitEntries()) {
      m_strategyChoice.findEffectiveStrategy(*pitEntry).afterNewNextHop(nextHop, pitEntry);
    }
  }
}

void
Forwarder::setExpiryTimer(const shared_ptr<pit::Entry>& pitEntry, time::milliseconds duration)
{
  BOOST_ASSERT(pitEntry);
  duration = std::max(duration, 0_ms);

  pitEntry->expiryTimer.cancel();
  pitEntry->expiryTimer = getScheduler().schedule(duration, [=] { onInterestFinalize(pitEntry); });
}

void
Forwarder::insertDeadNonceList(pit::Entry& pitEntry, const Face* upstream)
{
  // need Dead Nonce List insert?
  bool needDnl = true;
  if (pitEntry.isSatisfied) {
    BOOST_ASSERT(pitEntry.dataFreshnessPeriod >= 0_ms);
    needDnl = pitEntry.getInterest().getMustBeFresh() &&
              pitEntry.dataFreshnessPeriod < m_deadNonceList.getLifetime();
  }

  if (!needDnl) {
    return;
  }

  // Dead Nonce List insert
  if (upstream == nullptr) {
    // insert all outgoing Nonces
    const auto& outRecords = pitEntry.getOutRecords();
    std::for_each(outRecords.begin(), outRecords.end(), [&] (const auto& outRecord) {
      m_deadNonceList.add(pitEntry.getName(), outRecord.getLastNonce());
    });
  }
  else {
    // insert outgoing Nonce of a specific face
    auto outRecord = pitEntry.getOutRecord(*upstream);
    if (outRecord != pitEntry.getOutRecords().end()) {
      m_deadNonceList.add(pitEntry.getName(), outRecord->getLastNonce());
    }
  }
}

void
Forwarder::setConfigFile(ConfigFile& configFile)
{
  configFile.addSectionHandler(CFG_FORWARDER, [this] (auto&&... args) {
    processConfig(std::forward<decltype(args)>(args)...);
  });
}

void
Forwarder::processConfig(const ConfigSection& configSection, bool isDryRun, const std::string&)
{
  Config config;

  for (const auto& pair : configSection) {
    const std::string& key = pair.first;
    if (key == "default_hop_limit") {
      config.defaultHopLimit = ConfigFile::parseNumber<uint8_t>(pair, CFG_FORWARDER);
    }
    else {
      NDN_THROW(ConfigFile::Error("Unrecognized option " + CFG_FORWARDER + "." + key));
    }
  }

  if (!isDryRun) {
    m_config = config;
  }
}

} // namespace nfd

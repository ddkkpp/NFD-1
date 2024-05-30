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
#include <iostream>
#include <fstream>
#include <chrono>  

#include <ndn-cxx/lp/pit-token.hpp>
#include <ndn-cxx/lp/tags.hpp>

#include "face/null-face.hpp"
#include <deque>
#include <thread>
#include<math.h>

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
  
  SetWatchDog(500);
}

Forwarder::~Forwarder() = default;

void
Forwarder::probe(const Interest& interest, const FaceEndpoint& ingress){
  //NFD_LOG_DEBUG("start probing");
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
    //NFD_LOG_DEBUG("set nouce");
    probe->setName(*nameWithSequence);
    //NFD_LOG_DEBUG("probe is"<<probe->getName());
    
    ingress.face.sendInterest(*probe);
    auto seq=probe->getName().get(1).toSequenceNumber();
    probeFilter.Add(seq,0);//记录probe的name
    //NFD_LOG_DEBUG("add to probefilter: "<<seq);
    }
  }
  
}

void
Forwarder::onIncomingInterest(const Interest& interest, const FaceEndpoint& ingress)
{
  // receive Interest
  //NFD_LOG_DEBUG("onIncomingInterest in=" << ingress << " interest=" << interest.getName());
  interest.setTag(make_shared<lp::IncomingFaceIdTag>(ingress.face.getId()));
  ++m_counters.nInInterests;

  // drop if HopLimit zero, decrement otherwise (if present)
  if (interest.getHopLimit()) {
    if (*interest.getHopLimit() == 0) {
      //NFD_LOG_DEBUG("onIncomingInterest in=" << ingress << " interest=" << interest.getName()<< " hop-limit=0");
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
    //NFD_LOG_DEBUG("onIncomingInterest in=" << ingress<< " interest=" << interest.getName() << " violates /localhost");
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
    //NFD_LOG_DEBUG("onIncomingInterest in=" << ingress<< " interest=" << interest.getName() << " reaching-producer-region");
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

  //is pending?
  if (!pitEntry->hasInRecords()) {
    //NFD_LOG_DEBUG("没有PIT");
    m_cs.find(interest,
              [=] (const Interest& i, const Data& d, bool needVerifyTime) { onContentStoreHit(i, ingress, pitEntry, d, needVerifyTime); },
              [=] (const Interest& i) { onContentStoreMiss(i, ingress, pitEntry); });
  }
  else {
    //NFD_LOG_DEBUG("有PIT");
    this->onContentStoreMiss(interest, ingress, pitEntry);
  }
}

void
Forwarder::onInterestLoop(const Interest& interest, const FaceEndpoint& ingress)
{
  // if multi-access or ad hoc face, drop
  if (ingress.face.getLinkType() != ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    //NFD_LOG_DEBUG("onInterestLoop in=" << ingress<< " interest=" << interest.getName() << " drop");
    return;
  }

  //NFD_LOG_DEBUG("onInterestLoop in=" << ingress << " interest=" << interest.getName()<< " send-Nack-duplicate");

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
  //NFD_LOG_DEBUG("onContentStoreMiss interest=" << interest.getName());
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
      //NFD_LOG_DEBUG("onContentStoreMiss interest=" << interest.getName()<< " nexthop-faceid=" << nextHopFace->getId());
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
                             const shared_ptr<pit::Entry>& pitEntry, const Data& data, bool needVerifyTime)
{
  if(data.getSignatureInfo().getSignatureType()==255){
    goodhit++;
  }
  else{
    badhit++;
  }
  if(needVerifyTime){
    ++verificationTimes;
    //NFD_LOG_DEBUG(verificationTimes);
  }
  //NFD_LOG_DEBUG("onContentStoreHit interest=" << interest.getName());
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
 m_strategyChoice.findEffectiveStrategy(*pitEntry).afterContentStoreHit(data, ingress, pitEntry, needVerifyTime);
}

pit::OutRecord*
Forwarder::onOutgoingInterest(const Interest& interest, Face& egress,
                              const shared_ptr<pit::Entry>& pitEntry)
{
  // drop if HopLimit == 0 but sending on non-local face
  if (interest.getHopLimit() == 0 && egress.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL) {
    //NFD_LOG_DEBUG("onOutgoingInterest out=" << egress.getId() << " interest=" << pitEntry->getName()<< " non-local hop-limit=0");
    ++egress.getCounters().nOutHopLimitZero;
    return nullptr;
  }

  //NFD_LOG_DEBUG("onOutgoingInterest out=" << egress.getId() << " interest=" << pitEntry->getName());

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
  //NFD_LOG_DEBUG("onInterestFinalize interest=" << pitEntry->getName()<< (pitEntry->isSatisfied ? " satisfied" : " unsatisfied"));

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
  // receive Data
  //NFD_LOG_DEBUG("onIncomingData in=" << ingress << " data=" << data.getName());
  
  if(data.getSignatureInfo().getSignatureType()==100){
    //NFD_LOG_DEBUG("Kim方案:丢弃验证过的假包");
    return;
  }

  data.setTag(make_shared<lp::IncomingFaceIdTag>(ingress.face.getId()));
  ++m_counters.nInData;

  // /localhost scope control
  bool isViolatingLocalhost = ingress.face.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(data.getName());
  if (isViolatingLocalhost) {
    //NFD_LOG_DEBUG("onIncomingData in=" << ingress << " data=" << data.getName() << " violates /localhost");
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
  
//此处决定是否缓存
  // auto now=time::steady_clock::now();
  // auto Tmax=1000000000_ns;
  // auto Te=0_ns;
  // int count=0;
  // auto Te_ba=0_ns;
  // int count_ba=0;
  // double p;
  // //一个pitEntry对应一个interest，一个outrecord对应这个interest的一个上游端口
  // for (const auto& pitEntry : pitMatches) {
  //   for(const auto& outRecord:pitEntry->getOutRecords()){
  //       Te+= now - outRecord.getLastRenewed();
  //       ++count;
  //   }
  // }
  // //NFD_LOG_DEBUG("Te_sum = "<<Te<<", count = "<<count);
  // Te=Te/count;
  // //NFD_LOG_DEBUG("Te = "<<Te);

  // for (const auto& pitEntry : m_pit) {
  //   for(const auto& outRecord:pitEntry.getOutRecords()){
  //       Te_ba+= now - outRecord.getLastRenewed();
  //       ++count_ba;
  //   }
  // }
  // //NFD_LOG_DEBUG("Te_ba_sum = "<<Te_ba<<", count_ba = "<<count_ba);
  // Te_ba=Te_ba/count_ba;
  // //NFD_LOG_DEBUG("Te_ba = "<<Te_ba);

  // if(Te.count()<=std::min(Te_ba.count(),Tmax.count()/2)){
  //   //NFD_LOG_DEBUG("p=1");
  //   p=1;
  // }
  // else if((Te.count()>std::min(Te_ba.count(),Tmax.count()/2))&&(Te.count()<=std::max(Te_ba.count(),Tmax.count()/2))){
  //   p=1-double(Te.count()) / double(Tmax.count());
  //   //NFD_LOG_DEBUG("p=1-Te/Tmax= "<<p);
  // }
  // else if((Te.count()>std::max(Te_ba.count(),Tmax.count()/2))&&(Te.count()<Tmax.count())){
  //   p=pow((1-double(Te.count()) / double(Tmax.count())),2);
  //   //NFD_LOG_DEBUG("p=(1-Te/Tmax)**2== "<<p);
  // }
  // else{
  //   //NFD_LOG_DEBUG("p=0");
  //   p=0;
  // }

  // if((rand()/RAND_MAX)<p){
  //   //NFD_LOG_DEBUG("达到插入概率，可以插入");
  //   m_cs.insert(data);
  // }
  // CS insert


  m_cs.insert(data);


  std::set<std::pair<Face*, EndpointId>> satisfiedDownstreams;
  std::multimap<std::pair<Face*, EndpointId>, std::shared_ptr<pit::Entry>> unsatisfiedPitEntries;

  for (const auto& pitEntry : pitMatches) {
    //NFD_LOG_DEBUG("onIncomingData matching=" << pitEntry->getName());

    // invoke PIT satisfy callback
    beforeSatisfyInterest(*pitEntry, ingress.face, data);

    std::set<std::pair<Face*, EndpointId>> unsatisfiedDownstreams;
    nodeType=m_strategyChoice.findEffectiveStrategy(*pitEntry).satisfyInterest(pitEntry, ingress, data,
                                                                      satisfiedDownstreams, unsatisfiedDownstreams);

    //如果是假包，则在满足pit前就丢包                                                                 
    if(nodeType==verifyNode)
    {
      if(data.getSignatureInfo().getSignatureType()==1){
        return;//丢弃
      }
    }     
                                                     
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
  shared_ptr<ndn::SignatureInfo> signatureInfo1 = make_shared<ndn::SignatureInfo>(const_cast<ndn::SignatureInfo&>(data.getSignatureInfo()));
  if(nodeType==maliciousNode)
  {
    auto p=double(rand())/double(RAND_MAX);
    //NFD_LOG_DEBUG("攻击p="<<p);
    if(p<=1){
      signatureInfo1->setSignatureType(static_cast< ::ndn::tlv::SignatureTypeValue>(1));//1表示假包
      //NFD_LOG_DEBUG("modify signature maliciously, data=" << data.getName());
    }
  }
  // if(nodeType==verifyNode)
  // {
  //   //加验证延时
  //   if(data.getTag<ndn::lp::ExtraDelayTag>()!=nullptr){
  //         data1->setTag(make_shared<ndn::lp::ExtraDelayTag>(4+*(data.getTag<ndn::lp::ExtraDelayTag>())) );
  //   }
  //   if(data.getSignatureInfo().getSignatureType()==1){
  //     return;//丢弃
  //   }
  // }
  data1->setSignatureInfo(*signatureInfo1);
  //NFD_LOG_DEBUG("SignatureType = "<<data1->getSignatureInfo().getSignatureType());
  
  // foreach pending downstream
  for (const auto& downstream : satisfiedDownstreams) {
    if (downstream.first->getId() == ingress.face.getId() &&
        downstream.second == ingress.endpoint &&
        downstream.first->getLinkType() != ndn::nfd::LINK_TYPE_AD_HOC) {
      continue;
    }
    this->onOutgoingData(*data1, *downstream.first);
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

  //NFD_LOG_DEBUG("onDataUnsolicited in=" << ingress << " data=" << data.getName()<< " decision=" << decision);
  ++m_counters.nUnsolicitedData;
}

bool
Forwarder::onOutgoingData(const Data& data, Face& egress)
{
  if (egress.getId() == face::INVALID_FACEID) {
    NFD_LOG_WARN("onOutgoingData out=(invalid) data=" << data.getName());
    return false;
  }
  //NFD_LOG_DEBUG("onOutgoingData out=" << egress.getId() << " data=" << data.getName());

  // /localhost scope control
  bool isViolatingLocalhost = egress.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(data.getName());
  if (isViolatingLocalhost) {
    //NFD_LOG_DEBUG("onOutgoingData out=" << egress.getId() << " data=" << data.getName()<< " violates /localhost");
    // drop
    return false;
  }

  // TODO traffic manager

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
    //NFD_LOG_DEBUG("onIncomingNack in=" << ingress<< " nack=" << nack.getInterest().getName() << "~" << nack.getReason()<< " link-type=" << ingress.face.getLinkType());
    return;
  }

  // PIT match
  shared_ptr<pit::Entry> pitEntry = m_pit.find(nack.getInterest());
  // if no PIT entry found, drop
  if (pitEntry == nullptr) {
    //NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()<< "~" << nack.getReason() << " no-PIT-entry");
    return;
  }

  // has out-record?
  auto outRecord = pitEntry->getOutRecord(ingress.face);
  // if no out-record found, drop
  if (outRecord == pitEntry->out_end()) {
    //NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()<< "~" << nack.getReason() << " no-out-record");
    return;
  }

  // if out-record has different Nonce, drop
  if (nack.getInterest().getNonce() != outRecord->getLastNonce()) {
    //NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()<< "~" << nack.getReason() << " wrong-Nonce " << nack.getInterest().getNonce()<< "!=" << outRecord->getLastNonce());
    return;
  }

  //NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()<< "~" << nack.getReason() << " OK");

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
    //NFD_LOG_DEBUG("onOutgoingNack out=" << egress.getId()<< " nack=" << pitEntry->getInterest().getName()<< "~" << nack.getReason() << " no-in-record");
    return false;
  }

  // if multi-access or ad hoc face, drop
  if (egress.getLinkType() != ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    //NFD_LOG_DEBUG("onOutgoingNack out=" << egress.getId()<< " nack=" << pitEntry->getInterest().getName() << "~" << nack.getReason()<< " link-type=" << egress.getLinkType());
    return false;
  }

  //NFD_LOG_DEBUG("onOutgoingNack out=" << egress.getId()<< " nack=" << pitEntry->getInterest().getName()<< "~" << nack.getReason() << " OK");

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


void computeVerifyTimesWDCallback(Forwarder *ptr)
{
  if(ptr->goodhit+ptr->badhit!=0){
    NS_LOG_DEBUG("goodhit rate= "<<double(ptr->goodhit)/(double(ptr->goodhit+ptr->badhit)));
  }
  ptr->goodhit=0;
  ptr->badhit=0;

  ptr->unit_sequence+=1;
  if(ptr->verificationTimes!=0){
    std::ofstream outFile("/home/dkp/ndnSIM_new_kim/ns-3/verificationTimes.txt", std::ios::app); // 或者 outFile.open("output.txt", std::ofstream::app);

    if (outFile.is_open()) {
      outFile << ptr->unit_sequence << ":"<<ptr->verificationTimes<<std::endl;
      //NS_LOG_DEBUG("m_verificationTimes in this period = "<<ptr->verificationTimes);
      ptr->verificationTimes=0;
      ptr->computeVerifyTimesWD.Ping(ns3::MilliSeconds(500));
    }
    outFile.close();
  }
}
void 
Forwarder::SetWatchDog(double t)
{
    if (t > 0)
    {
        computeVerifyTimesWD.Ping(ns3::MilliSeconds(t));
        computeVerifyTimesWD.SetFunction(computeVerifyTimesWDCallback);
        computeVerifyTimesWD.SetArguments<Forwarder *>(this);
    }
}

} // namespace nfd

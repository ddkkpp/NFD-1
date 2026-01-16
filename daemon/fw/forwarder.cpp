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

#include <nanoflann.hpp>
#include <boost/math/distributions/fisher_f.hpp>
#include <boost/math/distributions/students_t.hpp>

#include <json/json.h>

#include "face/null-face.hpp"

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

  SetMetricsWatchDog(ns3::MilliSeconds(500));
}

Forwarder::~Forwarder() = default;

void
Forwarder::onIncomingInterest(const Interest& interest, const FaceEndpoint& ingress)
{
  // receive Interest
  NFD_LOG_DEBUG("onIncomingInterest in=" << ingress << " interest=" << interest.getName());
  NFD_LOG_DEBUG("scheme= "<<ingress.face.getRemoteUri().getScheme());
  if(ingress.face.getRemoteUri().getScheme() == "appFace"){
    NFD_LOG_DEBUG("is consumer node");
    isConsumerNode = true;//消费者节点的nodeid
  }
  //scheme类型有internal(初始建立路径)、appface（消费者节点从应用层获得的）和netdev（网络设备即非消费者节点从其他节点获得的）
  if(ingress.face.getRemoteUri().getScheme() == "netdev")
  {
      //获取seq一定要在判断scheme为非internal之后，否则会出现错误，
            //因为internal类型的兴趣包名形如/localhost/nfd/faces/events/seq=3，按照下面的方法获取seq会出现错误，
                //而且不会对该函数报错，而是仍然运行成功，但是log显示兴趣包转发不出去
      auto seq = interest.getName().get(1).toSequenceNumber();

      auto tagRead = *(interest.getTag<ndn::lp::ConsumerIdTag>());
        // 提取高16位
        uint16_t highBits = (tagRead >> 48) & 0xFFFF;
        // 提取中16位
        uint16_t middleBits = (tagRead >> 32) & 0xFFFF;
        // 提取低32位
        uint32_t lowBits = tagRead & 0xFFFFFFFF;
      NFD_LOG_DEBUG("Tag value: high16=" << highBits << ", mid16=" << middleBits<< ", low32=" << lowBits);
      if(highBits ==0){
        NFD_LOG_DEBUG("normal user interest received");
        numOfReceivedNormalUserInterest++;
      }
      else{
        NFD_LOG_DEBUG("malicious user interest received");
        numofMaliciousInterest++;
      }
      if(middleBits == 1){
        NFD_LOG_DEBUG("is edge node");
        isEdgeNode = true;
      }
      //中间16位设置为0，使得接下来的节点不会再判断为edge节点
      uint64_t tagWrite = tagRead & 0xFFFF0000FFFFFFFF;
      interest.setTag(make_shared<ndn::lp::ConsumerIdTag>(tagWrite));

      // //统计seq的数目到numOfInterest
      // if(numOfInterest.find(seq) == numOfInterest.end())
      // {
      //     numOfInterest[seq] = 1;
      // }
      // else
      // {
      //     numOfInterest[seq]++;
      // }
      numofAllInterest++;

      auto faceId = ingress.face.getId();
      NFD_LOG_DEBUG("faceId= "<<faceId);
      nfd::face::Transport* mytransport = ingress.face.getTransport();
      ns3::Ptr<ns3::Node> mynode =nullptr;
      ns3::Ptr<ns3::NetDevice> mydevice = dynamic_cast<ns3::ndn::NetDeviceTransport*>(mytransport)->GetNetDevice();
      ns3::Ptr<ns3::Channel> mychannel = mydevice->GetChannel();
      ns3::Ptr<ns3::PointToPointChannel> p2pChannel = mychannel->GetObject<ns3::PointToPointChannel>();
      ns3::Ptr<ns3::PointToPointNetDevice> p2pNetDevice = ns3::DynamicCast<ns3::PointToPointNetDevice>(p2pChannel->GetDevice(1));
      mynode = p2pNetDevice->GetNode();
      mynodeid = mynode->GetId();
      NFD_LOG_DEBUG("nodeid"<<mynodeid);
  }


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

  // is pending?
  if (!pitEntry->hasInRecords()) {
    m_cs.find(interest,
              [=] (const Interest& i, const Data& d) { onContentStoreHit(i, ingress, pitEntry, d); },
              [=] (const Interest& i) { onContentStoreMiss(i, ingress, pitEntry); });
  }
  else {
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

  auto tagRead = *(interest.getTag<ndn::lp::ConsumerIdTag>());
  // 提取高16位
  uint16_t highBits = (tagRead >> 48) & 0xFFFF;
  // 提取中16位
  uint16_t middleBits = (tagRead >> 32) & 0xFFFF;
  // 提取低32位
  uint32_t lowBits = tagRead & 0xFFFFFFFF;
  NFD_LOG_DEBUG("Tag value: high16=" << highBits << ", mid16=" << middleBits<< ", low32=" << lowBits);
  if(highBits ==0){
     NFD_LOG_DEBUG("normal user interest hit");
     numOfHitNormalUserInterest++;
  }

  ++m_counters.nCsHits;
  afterCsHit(interest, data);

  data.setTag(make_shared<lp::IncomingFaceIdTag>(face::FACEID_CONTENT_STORE));
  data.setTag(interest.getTag<lp::PitToken>());
  //若缓存命中，则hopcount置为0
  data.setTag(make_shared<lp::HopCountTag>(0));
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

  auto prefix = data.getName().getPrefix(-1);
  NFD_LOG_DEBUG("prefix= "<<prefix);
  if(prefix.toUri() == "/prefix"){
      auto seq = data.getName().get(1).toSequenceNumber();
      //统计流行内容和非流行内容收到数目
      if(seq<=2000){
        numOfPopularData++;
      }
      else{
        numOfUnpopularData++;
      }
  }

  m_cs.insert(data);

  std::set<std::pair<Face*, EndpointId>> satisfiedDownstreams;
  std::multimap<std::pair<Face*, EndpointId>, std::shared_ptr<pit::Entry>> unsatisfiedPitEntries;

  for (const auto& pitEntry : pitMatches) {
    NFD_LOG_DEBUG("onIncomingData matching=" << pitEntry->getName());

    // invoke PIT satisfy callback
    beforeSatisfyInterest(*pitEntry, ingress.face, data);

    std::set<std::pair<Face*, EndpointId>> unsatisfiedDownstreams;
    m_strategyChoice.findEffectiveStrategy(*pitEntry).satisfyInterest(pitEntry, ingress, data,
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

  // foreach pending downstream
  for (const auto& downstream : satisfiedDownstreams) {
    if (downstream.first->getId() == ingress.face.getId() &&
        downstream.second == ingress.endpoint &&
        downstream.first->getLinkType() != ndn::nfd::LINK_TYPE_AD_HOC) {
      continue;
    }

    this->onOutgoingData(data, *downstream.first);
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

void computeForwarderMetricsWDCallback(Forwarder *ptr)
{
  if(ptr->mynodeid==0){
    //producer节点
    NFD_LOG_INFO("is producer node");
    //清空数据
    ptr->numofAllInterest = 0;
    ptr->numofMaliciousInterest = 0;
    ptr->numOfHitNormalUserInterest = 0;
    ptr->numOfReceivedNormalUserInterest = 0;
    ptr->numOfNotCacheOfUnpopularData = 0;
    ptr->numOfUnpopularData = 0;
    ptr->numOfNotCacheOfPopularData = 0;
    ptr->numOfPopularData = 0;
    
    //如果不Ping直接return，会导致下一次不会再调用这个函数
    ptr->computeForwarderMetricsWD.Ping(ptr->metricsWatchdogPeriod);
    return;
  }
  if(ptr->isConsumerNode){
    //消费者节点
    NFD_LOG_INFO("is consumer node");
    //清空数据
    ptr->numofAllInterest = 0;
    ptr->numofMaliciousInterest = 0;
    ptr->numOfHitNormalUserInterest = 0;
    ptr->numOfReceivedNormalUserInterest = 0;
    ptr->numOfNotCacheOfUnpopularData = 0;
    ptr->numOfUnpopularData = 0;
    ptr->numOfNotCacheOfPopularData = 0;
    ptr->numOfPopularData = 0;
    
    //如果不Ping直接return，会导致下一次不会再调用这个函数
    ptr->computeForwarderMetricsWD.Ping(ptr->metricsWatchdogPeriod);
    return;
  }
  if(ptr->numofAllInterest == 0){
    //未启动节点（还没有发起攻击的攻击者）
    NFD_LOG_INFO("node not start");
    //清空数据
    ptr->numofAllInterest = 0;
    ptr->numofMaliciousInterest = 0;
    ptr->numOfHitNormalUserInterest = 0;
    ptr->numOfReceivedNormalUserInterest = 0;
    ptr->numOfNotCacheOfUnpopularData = 0;
    ptr->numOfUnpopularData = 0;
    ptr->numOfNotCacheOfPopularData = 0;
    ptr->numOfPopularData = 0;
  
    ptr->computeForwarderMetricsWD.Ping(ptr->metricsWatchdogPeriod);
    return;
  }

  double receivedMaliciousInterestRatio = 0;
  NFD_LOG_INFO("numofAllInterest= "<<ptr->numofAllInterest);
  NFD_LOG_INFO("numofMaliciousInterest= "<<ptr->numofMaliciousInterest);
  if(ptr->numofAllInterest!=0){
    receivedMaliciousInterestRatio = (double)ptr->numofMaliciousInterest / (double)ptr->numofAllInterest;
    NFD_LOG_INFO("receivedMaliciousInterestRatio= "<<receivedMaliciousInterestRatio);
  }

  double normalHitRatio = 0;
  NFD_LOG_INFO("numOfReceivedNormalUserInterest= "<<ptr->numOfReceivedNormalUserInterest);
  NFD_LOG_INFO("numOfHitNormalUserInterest= "<<ptr->numOfHitNormalUserInterest);
  if(ptr->numOfReceivedNormalUserInterest!=0){
    normalHitRatio = (double)ptr->numOfHitNormalUserInterest / (double)ptr->numOfReceivedNormalUserInterest;
    NFD_LOG_INFO("normalHitRatio= "<<normalHitRatio);
  }

  double detectionRatio = 0;
  //numOfNotCacheOfUnpopularData始终为0
  NFD_LOG_INFO("numOfUnpopularData= "<<ptr->numOfUnpopularData);
  NFD_LOG_INFO("numOfNotCacheOfUnpopularData= "<<ptr->numOfNotCacheOfUnpopularData);
  if(ptr->numOfUnpopularData!=0){
    detectionRatio = (double)ptr->numOfNotCacheOfUnpopularData / (double)ptr->numOfUnpopularData;
    NFD_LOG_INFO("detectionRatio= "<<detectionRatio);
  }

  double falseAlarmRatio = 0;
  //numOfNotCacheOfPopularData始终为0
  NFD_LOG_INFO("numOfPopularData= "<<ptr->numOfPopularData);
  NFD_LOG_INFO("numOfNotCacheOfPopularData= "<<ptr->numOfNotCacheOfPopularData);
  if(ptr->numOfPopularData!=0){
    falseAlarmRatio = (double)ptr->numOfNotCacheOfPopularData / (double)ptr->numOfPopularData;
    NFD_LOG_INFO("falseAlarmRatio= "<<falseAlarmRatio);
  }

  double cacheAccuracy = 0;
  int numOfCacheOfPopularData = ptr->numOfPopularData - ptr->numOfNotCacheOfPopularData;
  int numOfCacheOfUnpopularData = ptr->numOfUnpopularData - ptr->numOfNotCacheOfUnpopularData;
  NFD_LOG_INFO("numOfCacheOfPopularData= "<<numOfCacheOfPopularData);
  NFD_LOG_INFO("numOfCacheOfUnpopularData= "<<numOfCacheOfUnpopularData);
  if(numOfCacheOfPopularData+numOfCacheOfUnpopularData!=0){
    cacheAccuracy = (double)(numOfCacheOfPopularData) / (double)(numOfCacheOfPopularData+numOfCacheOfUnpopularData);
    NFD_LOG_INFO("cacheAccuracy= "<<cacheAccuracy);
  }
  //注意：这里的路径需要根据实际情况修改
  // std::ofstream outFile("/media/sf_ndnsim/ForwarderMetrics-empty.txt", std::ios::app); // 或者 outFile.open("output.txt", std::ofstream::app);
  // if (outFile.is_open()) {
  //   outFile << "nodeid="<<ptr->mynodeid<<" Hit= "<<normalHitRatio<<" DR= "<<detectionRatio<<" FR= "<<falseAlarmRatio<<std::endl;
  // }
  // outFile.close();

  //清空数据
  ptr->numofAllInterest = 0;
  ptr->numofMaliciousInterest = 0;
  ptr->numOfHitNormalUserInterest = 0;
  ptr->numOfReceivedNormalUserInterest = 0;
  ptr->numOfNotCacheOfUnpopularData = 0;
  ptr->numOfUnpopularData = 0;
  ptr->numOfNotCacheOfPopularData = 0;
  ptr->numOfPopularData = 0;

  ptr->computeForwarderMetricsWD.Ping(ptr->metricsWatchdogPeriod);
}

void 
Forwarder::SetMetricsWatchDog(ns3::Time t)
{
    if (t > ns3::MilliSeconds(0))
    {
        computeForwarderMetricsWD.Ping(t);
        computeForwarderMetricsWD.SetFunction(computeForwarderMetricsWDCallback);
        computeForwarderMetricsWD.SetArguments<Forwarder *>(this);
    }
}

} // namespace nfd

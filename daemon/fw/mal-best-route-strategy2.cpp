/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2019,  Regents of the University of California,
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

#include "mal-best-route-strategy2.hpp"
#include "algorithm.hpp"
#include "common/logger.hpp"

namespace nfd {
namespace fw {

NFD_LOG_INIT(MalBestRouteStrategy2);
NFD_REGISTER_STRATEGY(MalBestRouteStrategy2);

const time::milliseconds MalBestRouteStrategy2::RETX_SUPPRESSION_INITIAL(10);
const time::milliseconds MalBestRouteStrategy2::RETX_SUPPRESSION_MAX(250);

MalBestRouteStrategy2::MalBestRouteStrategy2(Forwarder& forwarder, const Name& name)
  : Strategy(forwarder)
  , ProcessNackTraits(this)
  , m_retxSuppression(RETX_SUPPRESSION_INITIAL,
                      RetxSuppressionExponential::DEFAULT_MULTIPLIER,
                      RETX_SUPPRESSION_MAX)
{
  ParsedInstanceName parsed = parseInstanceName(name);
  if (!parsed.parameters.empty()) {
    NDN_THROW(std::invalid_argument("MalBestRouteStrategy2 does not accept parameters"));
  }
  if (parsed.version && *parsed.version != getStrategyName()[-1].toVersion()) {
    NDN_THROW(std::invalid_argument(
      "MalBestRouteStrategy2 does not support version " + to_string(*parsed.version)));
  }
  this->setInstanceName(makeInstanceName(name, getStrategyName()));
}

const Name&
MalBestRouteStrategy2::getStrategyName()
{
  static const auto strategyName=Name("/localhost/nfd/strategy/mal-best-route/%FD%05").appendVersion(5);
  return strategyName;
}

void
MalBestRouteStrategy2::afterReceiveInterest(const Interest& interest, const FaceEndpoint& ingress,
                                        const shared_ptr<pit::Entry>& pitEntry)
{
  RetxSuppressionResult suppression = m_retxSuppression.decidePerPitEntry(*pitEntry);
  if (suppression == RetxSuppressionResult::SUPPRESS) {
    NFD_LOG_DEBUG(interest << " from=" << ingress << " suppressed");
    return;
  }

  const fib::Entry& fibEntry = this->lookupFib(*pitEntry);
  const fib::NextHopList& nexthops = fibEntry.getNextHops();
  auto it = nexthops.end();
  auto it2 = nexthops.end();
  auto it3 = nexthops.end();
  auto nexthops_size = nexthops.size();
  int nexthop_seq=1;
  auto p=double(rand())/double(RAND_MAX);

  if (suppression == RetxSuppressionResult::NEW) {
    // forward to nexthop with lowest cost except downstream
    it = std::find_if(nexthops.begin(), nexthops.end(), [&] (const auto& nexthop) {
      return isNextHopEligible(ingress.face, interest, nexthop, pitEntry);
    });

    if (it == nexthops.end()) {
      NFD_LOG_DEBUG(interest << " from=" << ingress << " noNextHop");

      lp::NackHeader nackHeader;
      nackHeader.setReason(lp::NackReason::NO_ROUTE);
      this->sendNack(nackHeader, ingress.face, pitEntry);
      this->rejectPendingInterest(pitEntry);
      return;
    }

    Face& outFace = it->getFace();
    NFD_LOG_DEBUG(interest << " from=" << ingress << " newPitEntry-to=" << outFace.getId());
    this->sendInterest(interest, outFace, pitEntry);
    return;
    // if(it != nexthops.end()){
    //   it2 = std::find_if(nexthops.begin(), nexthops.end(), [&] (const auto& nexthop) {
    //     return isNextHopEligible(ingress.face, interest, nexthop, pitEntry)&&(nexthop.getFace().getId()!=it->getFace().getId());
    //   });
    // }
    // if(it2 != nexthops.end()){
    //   it3 = std::find_if(nexthops.begin(), nexthops.end(), [&] (const auto& nexthop) {
    //     return isNextHopEligible(ingress.face, interest, nexthop, pitEntry)&&(nexthop.getFace().getId()!=it->getFace().getId())&&(nexthop.getFace().getId()!=it2->getFace().getId());
    //   });
    // }
    // if(it2 == nexthops.end()){//如果只有一个有效下一跳
    //     Face& outFace = it->getFace();
    //     NFD_LOG_DEBUG(interest << " from=" << ingress << " newPitEntry-to=" << outFace.getId());
    //     this->sendInterest(interest, outFace, pitEntry);
    //     return;
    // }
    // else if(it2 != nexthops.end() && it3 == nexthops.end()){//如果有两个有效下一跳
    //   if(p<=0.75){
    //     Face& outFace = it->getFace();
    //     NFD_LOG_DEBUG(interest << " from=" << ingress << " newPitEntry-to=" << outFace.getId());
    //     this->sendInterest(interest, outFace, pitEntry);
    //     return;
    //   }
    //   else{
    //     Face& outFace = it2->getFace();
    //     NFD_LOG_DEBUG(interest << " from=" << ingress << " newPitEntry-to=" << outFace.getId());
    //     this->sendInterest(interest, outFace, pitEntry);
    //     return;
    //   }
    // }
    // else{
    //   if(p<=0.5){
    //     Face& outFace = it->getFace();
    //     NFD_LOG_DEBUG(interest << " from=" << ingress << " newPitEntry-to=" << outFace.getId());
    //     this->sendInterest(interest, outFace, pitEntry);
    //     return;
    //   }
    //   else if(p<0.83){
    //     Face& outFace = it2->getFace();
    //     NFD_LOG_DEBUG(interest << " from=" << ingress << " newPitEntry-to=" << outFace.getId());
    //     this->sendInterest(interest, outFace, pitEntry);
    //     return;
    //   }
    //   else{
    //     Face& outFace = it3->getFace();
    //     NFD_LOG_DEBUG(interest << " from=" << ingress << " newPitEntry-to=" << outFace.getId());
    //     this->sendInterest(interest, outFace, pitEntry);
    //     return;
    //   }
    // }
  }

  // find an unused upstream with lowest cost except downstream
  it = std::find_if(nexthops.begin(), nexthops.end(),
                    [&, now = time::steady_clock::now()] (const auto& nexthop) {
                      return isNextHopEligible(ingress.face, interest, nexthop, pitEntry, true, now);
                    });

  if (it != nexthops.end()) {
    Face& outFace = it->getFace();
    this->sendInterest(interest, outFace, pitEntry);
    NFD_LOG_DEBUG(interest << " from=" << ingress << " retransmit-unused-to=" << outFace.getId());
    return;
  }

  // find an eligible upstream that is used earliest
  it = findEligibleNextHopWithEarliestOutRecord(ingress.face, interest, nexthops, pitEntry);
  if (it == nexthops.end()) {
    NFD_LOG_DEBUG(interest << " from=" << ingress << " retransmitNoNextHop");
  }
  else {
    Face& outFace = it->getFace();
    this->sendInterest(interest, outFace, pitEntry);
    NFD_LOG_DEBUG(interest << " from=" << ingress << " retransmit-retry-to=" << outFace.getId());
  }
}

void
MalBestRouteStrategy2::afterReceiveNack(const lp::Nack& nack, const FaceEndpoint& ingress,
                                    const shared_ptr<pit::Entry>& pitEntry)
{
  this->processNack(nack, ingress.face, pitEntry);
}

bool
MalBestRouteStrategy2::satisfyInterest(const shared_ptr<pit::Entry>& pitEntry,
                          const FaceEndpoint& ingress, const Data& data,
                          std::set<std::pair<Face*, EndpointId>>& satisfiedDownstreams,
                          std::set<std::pair<Face*, EndpointId>>& unsatisfiedDownstreams)
{
  NFD_LOG_DEBUG("satisfyInterest pitEntry=" << pitEntry->getName()
                << " in=" << ingress << " data=" << data.getName());

  NFD_LOG_DEBUG("onIncomingData matching=" << pitEntry->getName());

  auto now = time::steady_clock::now();

  // remember pending downstreams
  for (const pit::InRecord& inRecord : pitEntry->getInRecords()) {
    if (inRecord.getExpiry() > now) {
      satisfiedDownstreams.emplace(&inRecord.getFace(), 0);
    }
  }

  // invoke PIT satisfy callback
  beforeSatisfyInterest(data, ingress, pitEntry);
  return false;
}

// void
// MalBestRouteStrategy2::afterReceiveData(const Data& data, const FaceEndpoint& ingress, 
//                   const shared_ptr<pit::Entry>& pitEntry)
// {
//     NFD_LOG_DEBUG("afterReceiveData, modify signature maliciously, data=" << data.getName());
//     auto data_ = const_cast<Data&>(data);
//     data_.setFake();

//     this->beforeSatisfyInterest(data_, ingress, pitEntry);
//     this->sendDataToAll(data_, pitEntry, ingress.face);
// }

// void
// MalBestRouteStrategy2::beforeSatisfyInterest(const Data& data, const FaceEndpoint& ingress,
//                                 const shared_ptr<pit::Entry>& pitEntry)
// {
//     NFD_LOG_DEBUG("beforeSatisfyInterest pitEntry=" << pitEntry->getName()
//                   << " in=" << ingress << " data=" << data.getName());
//     auto data_ = const_cast<Data&>(data);
//     data_.setFake();
//     NFD_LOG_DEBUG("afterReceiveData, modify signature maliciously, data=" << data.getName());
//     this->beforeSatisfyInterest(data_, ingress, pitEntry);
//     this->sendDataToAll(data_, pitEntry, ingress.face);
// }

bool
MalBestRouteStrategy2::sendData(const Data& data, Face& egress, const shared_ptr<pit::Entry>& pitEntry)
{
    shared_ptr<Data> data1 = make_shared<Data>(const_cast<Data&>(data));
    shared_ptr<ndn::SignatureInfo> signatureInfo1 = make_shared<ndn::SignatureInfo>(const_cast<ndn::SignatureInfo&>(data.getSignatureInfo()));
    signatureInfo1->setSignatureType(static_cast< ::ndn::tlv::SignatureTypeValue>(1));//1表示假包

    data1->setSignatureInfo(*signatureInfo1);
    NFD_LOG_DEBUG("afterReceiveData, modify signature maliciously, data=" << data.getName());
    NFD_LOG_DEBUG("SignatureType = "<<data1->getSignatureInfo().getSignatureType());
    return Strategy::sendData(*data1, egress, pitEntry);
}

void
MalBestRouteStrategy2::afterContentStoreHit(const Data& data, const FaceEndpoint& ingress,
                               const shared_ptr<pit::Entry>& pitEntry, bool needVerifyDelay)
{
    shared_ptr<Data> data1 = make_shared<Data>(const_cast<Data&>(data));
    shared_ptr<ndn::SignatureInfo> signatureInfo1 = make_shared<ndn::SignatureInfo>(const_cast<ndn::SignatureInfo&>(data.getSignatureInfo()));
    signatureInfo1->setSignatureType(static_cast< ::ndn::tlv::SignatureTypeValue>(1));//1表示假包

    data1->setSignatureInfo(*signatureInfo1);
    NFD_LOG_DEBUG("afterReceiveData, modify signature maliciously, data=" << data.getName());
    NFD_LOG_DEBUG("SignatureType = "<<data1->getSignatureInfo().getSignatureType());

    Strategy::afterContentStoreHit(*data1,ingress,pitEntry, needVerifyDelay);
}
} // namespace fw
} // namespace nfd

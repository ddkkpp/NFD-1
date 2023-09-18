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

#include "best-route-strategy.hpp"
#include "algorithm.hpp"
#include "common/logger.hpp"//自己加的
#include "strategy.hpp"
#include "forwarder.hpp"

#include <ndn-cxx/lp/pit-token.hpp>

#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm/copy.hpp>
#include "ns3/simulator.h"
//#include <linux/delay.h>

namespace nfd {
namespace fw {

BestRouteStrategyBase::BestRouteStrategyBase(Forwarder& forwarder)
  : Strategy(forwarder)
{
}

void
BestRouteStrategyBase::afterReceiveInterest(const FaceEndpoint& ingress, const Interest& interest,
                                            const shared_ptr<pit::Entry>& pitEntry)
{
  //usleep(4000);
  if (hasPendingOutRecords(*pitEntry)) {
    // not a new Interest, don't forward
    return;
  }
  const fib::Entry& fibEntry = this->lookupFib(*pitEntry);

  for (const auto& nexthop : fibEntry.getNextHops()) {
    Face& outFace = nexthop.getFace();
    if (!wouldViolateScope(ingress.face, interest, outFace) &&
        canForwardToLegacy(*pitEntry, outFace)) {
      this->sendInterest(pitEntry, FaceEndpoint(outFace, 0), interest);
      return;
    }
  }

  this->rejectPendingInterest(pitEntry);
}

//自己加的
void
BestRouteStrategyBase::afterReceiveData(const shared_ptr<pit::Entry>& pitEntry,
                           const FaceEndpoint& ingress, const Data& data)
{
  //NFD_LOG_DEBUG("afterReceiveData pitEntry=" << pitEntry->getName()
  //              << " in=" << ingress << " data=" << data.getName());
  
  //udelay(10);
  //usleep(4000);//运行变慢但结果不变
  //weak_ptr
  this->beforeSatisfyInterest(pitEntry, ingress, data);
  //std::cout<<ns3::Simulator::Now()<<std::endl;
  //Simulator::Schedule(Seconds(10.0), ndn::LinkControlHelper::FailLink, nodes.Get(0), nodes.Get(1));
  //ns3::Simulator::Schedule(ns3::Seconds(0.1),&void(nfd::fw::Strategy::sendDataToAll),pitEntry, ingress, data);
  //nfd::fw::Strategy inst;
  //ns3::Ptr<BestRouteStrategyBase> ins0=nfd::fw::BestRouteStrategyBase(nfd::Forwarder(FaceTable()));
  //nfd::fw::BestRouteStrategyBase ins(nfd::Forwarder(FaceTable()));
  //std::cout<<ns3::Simulator::Now()<<std::endl;
  //Time time=ns3::Simulator::Now();
  //std::cout<<ns3::Simulator::Now().GetMicroSeconds()<<std::endl;
  //Scheduler::scheduleEvent(const time::nanoseconds& after, const Event& event)
  //schedule（time,...)：当前时刻延迟time；在time时刻？
  //ns3::Simulator::Schedule(ns3::MilliSeconds(4),&nfd::fw::BestRouteStrategy::sendDataToAll,this, pitEntry, ingress, data);//bad weak_ptr
  //ns3::Simulator::Schedule(ns3::Seconds(4),&nfd::fw::BestRouteStrategy::sendDataToAll,this, pitEntry, ingress, data);//运行完但没有data
  //ns3::Simulator::Schedule(ns3::Seconds(ns3::Simulator::Now().GetSeconds()),&nfd::fw::BestRouteStrategy::sendDataToAll,this, pitEntry, ingress, data);
  //ns3::Simulator::ScheduleNow(&nfd::fw::BestRouteStrategyBase::sendDataToAll,this, pitEntry, ingress, data);//bad weak_ptr
  //ns3::Simulator::DoSchedule(ns3::Seconds(1.0),ns3::MakeEvent(nfd::fw::Strategy::sendDataToAll(pitEntry, ingress, data),pitEntry, ingress, data);
  //std::cout<<ns3::Seconds(ns3::Simulator::Now().GetSeconds()+1.0)<<std::endl;
  this->sendDataToAll(pitEntry, ingress, data);
}

NFD_REGISTER_STRATEGY(BestRouteStrategy);

BestRouteStrategy::BestRouteStrategy(Forwarder& forwarder, const Name& name)
  : BestRouteStrategyBase(forwarder)
{
  ParsedInstanceName parsed = parseInstanceName(name);
  if (!parsed.parameters.empty()) {
    NDN_THROW(std::invalid_argument("BestRouteStrategy does not accept parameters"));
  }
  if (parsed.version && *parsed.version != getStrategyName()[-1].toVersion()) {
    NDN_THROW(std::invalid_argument(
      "BestRouteStrategy does not support version " + to_string(*parsed.version)));
  }
  this->setInstanceName(makeInstanceName(name, getStrategyName()));
}

const Name&
BestRouteStrategy::getStrategyName()
{
  static Name strategyName("/localhost/nfd/strategy/best-route/%FD%01");
  return strategyName;
}

} // namespace fw
} // namespace nfd

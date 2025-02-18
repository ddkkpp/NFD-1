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

#ifndef NFD_DAEMON_FW_FORWARDER_HPP
#define NFD_DAEMON_FW_FORWARDER_HPP

#include "cuckoofilter/cuckoofilter.h"
#include "face-table.hpp"
#include "forwarder-counters.hpp"
#include "unsolicited-data-policy.hpp"
#include "common/config-file.hpp"
#include "face/face-endpoint.hpp"
#include "table/fib.hpp"
#include "table/pit.hpp"
#include "table/cs.hpp"
#include "table/measurements.hpp"
#include "table/strategy-choice.hpp"
#include "table/dead-nonce-list.hpp"
#include "table/network-region-table.hpp"
#include "ns3/watchdog.h"
#include "ns3/nstime.h"
#include "ns3/random-variable-stream.h"
#include <map>
#include <set>
#include <vector>
#include "ndn-cxx/util/scheduler.hpp"
#include "ns3/simulator.h"
#include <chrono>  
#include <boost/bimap.hpp>//必须放在最后include，不然error:reference to ‘_1’ is ambiguous,extern const _Placeholder<3> _3;

namespace nfd {

namespace fw {
class Strategy;
} // namespace fw

/**
 * \brief Main class of NFD's forwarding engine.
 *
 *  Forwarder owns all tables and implements the forwarding pipelines.
 */
class Forwarder
{
public:
  explicit
  Forwarder(FaceTable& faceTable);

  NFD_VIRTUAL_WITH_TESTS
  ~Forwarder();

  void 
  probe(const Interest& interest, const FaceEndpoint& ingress);

  const ForwarderCounters&
  getCounters() const
  {
    return m_counters;
  }

  fw::UnsolicitedDataPolicy&
  getUnsolicitedDataPolicy() const
  {
    return *m_unsolicitedDataPolicy;
  }

  void
  setUnsolicitedDataPolicy(unique_ptr<fw::UnsolicitedDataPolicy> policy)
  {
    BOOST_ASSERT(policy != nullptr);
    m_unsolicitedDataPolicy = std::move(policy);
  }

  NameTree&
  getNameTree()
  {
    return m_nameTree;
  }

  Fib&
  getFib()
  {
    return m_fib;
  }

  Pit&
  getPit()
  {
    return m_pit;
  }

  Cs&
  getCs()
  {
    return m_cs;
  }

  Measurements&
  getMeasurements()
  {
    return m_measurements;
  }

  StrategyChoice&
  getStrategyChoice()
  {
    return m_strategyChoice;
  }

  DeadNonceList&
  getDeadNonceList()
  {
    return m_deadNonceList;
  }

  NetworkRegionTable&
  getNetworkRegionTable()
  {
    return m_networkRegionTable;
  }

  /** \brief register handler for forwarder section of NFD configuration file
   */
  void
  setConfigFile(ConfigFile& configFile);

public:
    size_t goodhit=0;
  size_t badhit=0;
  size_t verificationTimes=0;
   ns3::Watchdog computeVerifyTimesWD;
   size_t unit_sequence=0;
  /** \brief trigger before PIT entry is satisfied
   *  \sa Strategy::beforeSatisfyInterest
   */
  signal::Signal<Forwarder, pit::Entry, Face, Data> beforeSatisfyInterest;

  /** \brief trigger before PIT entry expires
   *  \sa Strategy::beforeExpirePendingInterest
   */
  signal::Signal<Forwarder, pit::Entry> beforeExpirePendingInterest;

  /** \brief Signals when the incoming interest pipeline gets a hit from the content store
   */
  signal::Signal<Forwarder, Interest, Data> afterCsHit;

  /** \brief Signals when the incoming interest pipeline gets a miss from the content store
   */
  signal::Signal<Forwarder, Interest> afterCsMiss;

NFD_PUBLIC_WITH_TESTS_ELSE_PRIVATE: // pipelines
  /** \brief incoming Interest pipeline
   *  \param interest the incoming Interest, must be well-formed and created with make_shared
   *  \param ingress face on which \p interest was received and endpoint of the sender
   */
  NFD_VIRTUAL_WITH_TESTS void
  onIncomingInterest(const Interest& interest, const FaceEndpoint& ingress);

  /** \brief Interest loop pipeline
   */
  NFD_VIRTUAL_WITH_TESTS void
  onInterestLoop(const Interest& interest, const FaceEndpoint& ingress);

  /** \brief Content Store miss pipeline
  */
  NFD_VIRTUAL_WITH_TESTS void
  onContentStoreMiss(const Interest& interest, const FaceEndpoint& ingress,
                     const shared_ptr<pit::Entry>& pitEntry);

  /** \brief Content Store hit pipeline
  */
  NFD_VIRTUAL_WITH_TESTS void
  onContentStoreHit(const Interest& interest, const FaceEndpoint& ingress,
                   const shared_ptr<pit::Entry>& pitEntry, const Data& data, bool needVerifyTime);

  /** \brief outgoing Interest pipeline
   *  \return A pointer to the out-record created or nullptr if the Interest was dropped
   */
  NFD_VIRTUAL_WITH_TESTS pit::OutRecord*
  onOutgoingInterest(const Interest& interest, Face& egress,
                     const shared_ptr<pit::Entry>& pitEntry);

  /** \brief Interest finalize pipeline
   */
  NFD_VIRTUAL_WITH_TESTS void
  onInterestFinalize(const shared_ptr<pit::Entry>& pitEntry);

  /** \brief incoming Data pipeline
   *  \param data the incoming Data, must be well-formed and created with make_shared
   *  \param ingress face on which \p data was received and endpoint of the sender
   */
  NFD_VIRTUAL_WITH_TESTS void
  onIncomingData(const Data& data, const FaceEndpoint& ingress);

  /** \brief Data unsolicited pipeline
   */
  NFD_VIRTUAL_WITH_TESTS void
  onDataUnsolicited(const Data& data, const FaceEndpoint& ingress);

  /** \brief outgoing Data pipeline
   *  \return Whether the Data was transmitted (true) or dropped (false)
   */
  NFD_VIRTUAL_WITH_TESTS bool
  onOutgoingData(const Data& data, Face& egress);

  /** \brief incoming Nack pipeline
   *  \param nack the incoming Nack, must be well-formed
   *  \param ingress face on which \p nack is received and endpoint of the sender
   */
  NFD_VIRTUAL_WITH_TESTS void
  onIncomingNack(const lp::Nack& nack, const FaceEndpoint& ingress);

  /** \brief outgoing Nack pipeline
   *  \return Whether the Nack was transmitted (true) or dropped (false)
   */
  NFD_VIRTUAL_WITH_TESTS bool
  onOutgoingNack(const lp::NackHeader& nack, Face& egress,
                 const shared_ptr<pit::Entry>& pitEntry);

  NFD_VIRTUAL_WITH_TESTS void
  onDroppedInterest(const Interest& interest, Face& egress);

  NFD_VIRTUAL_WITH_TESTS void
  onNewNextHop(const Name& prefix, const fib::NextHop& nextHop);

private:
  /** \brief set a new expiry timer (now + \p duration) on a PIT entry
   */
  void
  setExpiryTimer(const shared_ptr<pit::Entry>& pitEntry, time::milliseconds duration);

  /** \brief insert Nonce to Dead Nonce List if necessary
   *  \param upstream if null, insert Nonces from all out-records;
   *                  if not null, insert Nonce only on the out-records of this face
   */
  void
  insertDeadNonceList(pit::Entry& pitEntry, const Face* upstream);

  void
  processConfig(const ConfigSection& configSection, bool isDryRun,
                const std::string& filename);

  void SetWatchDog(double t);

NFD_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  /**
   * \brief Configuration options from "forwarder" section
   */
  struct Config
  {
    /// Initial value of HopLimit that should be added to Interests that don't have one.
    /// A value of zero disables the feature.
    uint8_t defaultHopLimit = 0;
  };
  Config m_config;

private:
  ForwarderCounters m_counters;

  FaceTable& m_faceTable;
  unique_ptr<fw::UnsolicitedDataPolicy> m_unsolicitedDataPolicy;

  NameTree           m_nameTree;
  Fib                m_fib;
  Pit                m_pit;
  Cs                 m_cs;
  Measurements       m_measurements;
  StrategyChoice     m_strategyChoice;
  DeadNonceList      m_deadNonceList;
  NetworkRegionTable m_networkRegionTable;
  shared_ptr<Face>   m_csFace;
  cuckoofilter::CuckooFilter<uint64_t, 12> dataFilter=cuckoofilter::CuckooFilter<uint64_t, 12>(10000);
  cuckoofilter::CuckooFilter<uint64_t, 12> probeFilter=cuckoofilter::CuckooFilter<uint64_t, 12>(500);//设置大一点避免查询假阴性
  size_t nSendTotalProbe=11;//发送总的探测包数量
  uint32_t ei_now=0; 
  boost::bimap<FaceEndpoint,uint32_t> face_ei;//存储face和ei的对应关系
  std::set<FaceEndpoint> face_info;//存储可修改（删除然后插入）的FaceInfo
  bool isProbing=false;
  bool allFaceReceiveEnoughProbe=false;
  bool m_isHonest=true;
  ::ns3::Ptr<::ns3::UniformRandomVariable> m_rand;
  size_t deque_capacity=12;//反馈的包不能用于探测，因为不在邻居缓存中
  //face::Face& laterFbFace;
  std::vector<ndn::Interest> laterFeedback;
  bool finishProbing=false;
  //chrono::system_clock::time_point start_time, end_time; 
  //ndn::Scheduler s;



  // allow Strategy (base class) to enter pipelines
  friend class fw::Strategy;
};

} // namespace nfd

#endif // NFD_DAEMON_FW_FORWARDER_HPP

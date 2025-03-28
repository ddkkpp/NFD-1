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
#include <queue>
#include <map>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <set>
#include <algorithm>
#include <random>
#include <iostream>
#include <sstream>
#include <openssl/md5.h>
#include "ns3/watchdog.h"
#include "ns3/nstime.h"
#include "ns3/simulator.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/point-to-point-layout-module.h"
#include "ns3/ptr.h"
#include "ns3/net-device.h"
#include "ns3/channel.h"
#include "ns3/node.h"
#include "ns3/ndnSIM/model/ndn-net-device-transport.hpp"

namespace nfd {

namespace fw {
class Strategy;
} // namespace fw

/**
 * \brief Main class of NFD's forwarding engine.
 *
 * The Forwarder class owns all tables and implements the forwarding pipelines.
 */
class Forwarder
{
public:
  explicit
  Forwarder(FaceTable& faceTable);

  NFD_VIRTUAL_WITH_TESTS
  ~Forwarder();

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

  // 声明SetWatchDog函数
  void SetDetectWatchDog(ns3::Time interval);
  void SetMetricsWatchDog(ns3::Time interval);

  ns3::Watchdog detectWD; 
  ns3::Time detectWatchdogPeriod = ns3::MilliSeconds(1000);
  ns3::Watchdog computeForwarderMetricsWD;
  ns3::Time metricsWatchdogPeriod = ns3::MilliSeconds(500);

  std::map<uint64_t, int> numOfInterest;//每个内容名的请求数量
  std::map<uint64_t, std::unordered_set<uint64_t>> n_u;//每个内容名的不同用户
  std::unordered_set<uint64_t> n;//不同用户
  std::map<uint64_t, double> rho;//每个内容名的流行度
  // std::map<uint64_t, double> av;//每个内容名的平均请求强度
  double lambda = 0.8187;//流行度衰减常数,此处lambda对应论文中e^(-lambda)=e^(-0.2)=0.8187
  uint timesOfStdOfav = 3;//av的标准差的倍数
  uint timesOfStdOfr = 3;//r的标准差的倍数
  uint timesOfStdOfrho = -1;//rho的标准差的倍数
  double thr_av;//平均请求强度的阈值
  double thr_r;//请求强度的阈值
  double thr_rho;//流行度的阈值
  int wdCount = 0;//watchdog计数
  std::unordered_set<uint64_t> malicious;//恶意


  int mynodeid=10000;//节点id,取10000避免与其他节点id重复
  bool isEdgeNode = false;
  bool isConsumerNode = false;

  int numOfReceivedNormalUserInterest = 0;//收到正常用户请求的数量
  int numOfHitNormalUserInterest = 0;//正常用户请求命中的数量

  int numOfUnpopularData = 0;//遇到不流行内容的数量
  int numOfPopularData = 0;//遇到流行内容的数量
  int numOfNotCacheOfUnpopularData = 0;//遇到不流行内容不缓存的数量
  int numOfNotCacheOfPopularData = 0;//遇到流行内容不缓存的数量

  int numofMaliciousInterest = 0;//恶意请求数量
  int numofAllInterest = 0;//总请求数量
  int numofAllInterest1 = 0;//总请求数量
  int seqofMaliciousInterest = 9800;//恶意请求的seq

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
                    const shared_ptr<pit::Entry>& pitEntry, const Data& data);

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

  // allow Strategy (base class) to enter pipelines
  friend class fw::Strategy;
};

} // namespace nfd

#endif // NFD_DAEMON_FW_FORWARDER_HPP

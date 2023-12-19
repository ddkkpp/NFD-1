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

  // void SetWatchDog(ns3::Time t);
    void SetWatchDog(double t);

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
  
  ns3::Watchdog computePITWD;  
  ns3::Time PitTimeout = ns3::Seconds(2);
  int m=10;
  ns3::Time avgTotalDelay;//所有前缀的延迟的平均值
  ns3::Time DH=PitTimeout*4/5;
  int totalPit=0;//总占据pit
  std::queue<int> totalPitSeries;
  int avgTotalPit=0;
  int minAllocPit=100;//每个前缀的pit初步上限
  int minAcceptRate=500;//每个前缀的兴趣包速率初步上限
  std::unordered_set<std::string> allPrefix;//经过的前缀
  int pitTotalCapacity=1000;//总共Pit容量限制
  int unallocPitCapacity=1000;//未分配pit容量
  int curUnallocPit=0;//未分配pit空间中的占据量
  std::unordered_set<std::string> unallocName;//未分配空间中占据的pit完整name

  std::map<std::string, std::queue<int>> pitSeries;//每个前缀的历史pit序列，滑动更新
  std::map<std::string, int> curPit;//每个前缀的当前pit
  std::map<std::string, int> avgPit;//每个前缀的平均pit

  std::map<std::string, int> allocPit;//每个前缀分配的pit容量
  //std::map<std::string, double> tao;//每个前缀的波动状态
  double tao=1;//波动状态
  std::map<std::string, int> rate;//每个前缀的兴趣包到达速率
  std::map<std::string, int> numInterest;//每个前缀在当前周期的兴趣包到达数目

  std::unordered_set<std::string> suspectPrefix;//速率超标的可疑前缀
  //std::unordered_set<std::string> curMaliciousPrefix;//当前恶意前缀
  std::unordered_set<std::string> maliciousPrefix;//恶意前缀

  int timePitSeries=0;
  int timeDelaySeries=0;
  int count=0;
  int countSmallPeriod=0;
  ns3::Time watchdogPeriod = ns3::MilliSeconds(50);//单位毫秒

  std::map<std::string, ns3::Time> sendInterestTime;//每个兴趣包（完整名字，非前缀）的到达时刻
  std::map<std::string, std::vector<ns3::Time>> delaySeries;//每个前缀的历史delay序列，周期刷新
  std::map<std::string, ns3::Time> avgDelay;//每个前缀的平均delay
  std::map<std::string, double> deltaRateDelay;//每个前缀的delay变化比例
  std::map<std::string, int> numData;//每个前缀到来的数据包数目
  std::map<std::string, int> numDropInterest;//每个前缀未响应的兴趣包数目

  std::map<face::Face, int> numInterestOfFace;//每个端口在当前周期的兴趣包到达数目，用以计算rate
  std::map<face::Face, int> rateOfFace;//每个前缀的兴趣包到达速率
  int avgRateOfAllFace=0;
  std::map<std::pair<face::Face, std::string>, int> numInterestOfFacePrefix;//每个端口在当前周期的每个前缀的兴趣包到达数目，用以计算恶意请求比例
  std::map<face::Face, double> malirateOfFace;//每个端口的恶意前缀兴趣包占总兴趣包比例
  std::map<face::Face, std::vector<ns3::Time>> delaySeriesOfFace;//每个端口的历史delay序列，每500ms计算小周期平均delay
  std::map<face::Face, std::vector<ns3::Time>> avgDelaySeriesOfFace;//每个端口的小周期（500ms)平均delay序列，用以计算大周期（5s）平均delay
  std::map<face::Face, int> numDropInterestOfFace;//每个端口未响应的兴趣包数目
  std::map<face::Face, ns3::Time> avgDelayOfFace;//每个端口的平均delay
  ns3::Time avgDelayOfAllFace=ns3::MilliSeconds(0);
  std::unordered_set<face::Face> suspectFace;//可疑端口
  std::unordered_set<face::Face> maliciousFace;//恶意端口
  


  int mynodeid=0;
  std::map<std::string, int> noData;
  int BTNkId=5;
  std::unordered_set<int> edgeId={5};

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

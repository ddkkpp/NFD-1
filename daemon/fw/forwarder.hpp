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



 std::map<int, std::vector<FaceId>> 
 runSimpleClustering(const std::vector<std::pair<FaceId, size_t>>& data, size_t xi, size_t tau);



std::vector<std::vector<bool>> 
convertToBoolSeries(const std::map<FaceId, std::vector<uint64_t>>& contentSeries, std::vector<FaceId>& faceIdList);

 std::vector<int> 
 sigGen(const std::vector<std::vector<bool>>& matrix);

 std::vector<std::vector<int>> 
 sigMatrixGen(const std::vector<std::vector<bool>>& inputMatrix, int n);

 std::string 
 computeMD5(const std::string& str);

 std::map<int, std::vector<FaceId>> 
 minHashLSH(const std::vector<std::vector<bool>>& inputMatrix, int b, int r, const std::vector<FaceId>& faceIdList);

double 
calculateVariance(const std::vector<int64_t>& data, double mean);

double 
calculateMean(const std::vector<int64_t>& data);

bool 
fTest(double var1, double var2, size_t size1, size_t size2, double alpha);

bool 
tTest(double mean1, double mean2, double var1, double var2, 
      size_t size1, size_t size2, double alpha);

void 
performTests(std::map<int, std::vector<FaceId>>& data, 
            const std::map<FaceId, std::vector<int64_t>>& lastIntervalSeriesOfFace, 
            double alpha, std::set<FaceId>& finalSuspect1);

void 
performIsolationForestDetection(std::set<FaceId>& finalSuspect2);

//   struct Point {
//       std::vector<int64_t> values;
//       int clusterId;
//   };

//  double 
//  euclideanDistance(const std::vector<int64_t>& a, const std::vector<int64_t>& b);

//  double 
//  vectorNorm(const std::vector<int64_t>& vec);

//  double 
//  minEuclideanDistance(const std::vector<int64_t>& a, const std::vector<int64_t>& b, int k);

//  std::vector<int> 
//  regionQuery(const std::vector<Point>& points, int pointIdx, double eps, int k);

//  void 
//  expandCluster(std::vector<Point>& points, int pointIdx, int clusterId, double eps, int minPts, int k);

//  std::unordered_map<int, std::vector<int>> 
//  dbscan(std::vector<Point>& points, double eps, int minPts, int k);

  // 声明SetWatchDog函数
  void SetWatchDog(ns3::Time interval);

  ns3::Watchdog detectWD; 
  ns3::Time watchdogPeriod = ns3::MilliSeconds(1000);

  std::map<FaceId, std::vector<uint64_t>> lastContentSeriesOfFace;//端口在上个周期内的请求的内容序列（假设前缀都一样，只统计序列号）
  std::map<FaceId, std::vector<int64_t>> lastIntervalSeriesOfFace;//端口在上个周期内的请求时间间隔序列
  std::map<FaceId, std::vector<uint64_t>> nowContentSeriesOfFace;//端口在这个周期内的请求的内容序列
  std::map<FaceId, std::vector<int64_t>> nowIntervalSeriesOfFace;//端口在这个周期内的请求时间间隔序列
  std::map<FaceId, ns3::Time> lastInterestTimeOfFace;//端口上次请求的时刻
  std::map<FaceId, ns3::Time> firstInterestTimeOfFace;//端口首次请求的时刻
  std::map<FaceId, FaceId> theFirstFaceInNearRangeOfFace;//端口所属的近邻区域的首个端口
  std::map<FaceId, FaceId> theLastFaceInNearRangeOfFace;//端口所属的近邻区域的首个端口
  FaceId curFirstFaceInNearRange;//当前近邻区域的首个端口
  FaceId curLastFaceInNearRange;//当前近邻区域的最后端口
  ns3::Time curStartTime;//当前范围内的首次请求的时刻
  int64_t maxAcceptableDelay = ns3::MilliSeconds(100).GetMicroSeconds();//最大可接受的延迟
  // std::map<FaceId, int64_t> relativeDelayToCurStartOfFace;//端口首个请求距离当前起点的时刻
  // std::map<FaceId, int64_t> maxDelayToCurStartOfFace;//当前范围内距离当前起点的最大延迟
  //端口在当前采样窗口内的首次请求时刻（窗口内第一个能获知距离前一个包的interval的包）
  //由于新的窗口开始总是空的，若当前窗口是第一个窗口，则该值为当前窗口内的第二个包，若当前窗口不是第一个窗口，则该值为当前窗口内的第一个包
  std::map<FaceId, ns3::Time> firstInterestTimeInCurWndOfFace;
  std::map<FaceId, bool> hasInterestOfFace;//端口是否有过请求

  std::map<FaceId, int64_t> validRangeOfFace;//端口请求的有效内容范围


  std::set<FaceId> finalSuspect1;//基于用户请求间相似性识别得到的可疑用户
  std::set<FaceId> finalSuspect2;//基于用户单位速率所请求的有效范围的异常检测得到的可疑用户
  std::set<FaceId> finalSuspect;//合并finalSuspect1和finalSuspect2
  double popularRateLimit = 0.1;//流行度阈值(在默认设置下，正常用户的该值为0.4～0.5)
  std::set<FaceId> Malicious;//恶意


  int mynodeid=0;//节点id
  std::unordered_set<int> edgeId={2};//消费者边缘节点

  //space-saving算法的存储结构
  std::unordered_map<uint64_t, int> curSequenceMap;
  std::unordered_map<uint64_t, int> lastSequenceMap;
  std::unordered_map<uint64_t, int> lastLastSequenceMap;
  size_t sequenceMapCapacity = 200;

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

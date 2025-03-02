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

#include "matplotlibcpp.h"
#include <cmath>
#include <limits>

namespace plt = matplotlibcpp;

namespace nfd {

NFD_LOG_INIT(Forwarder);

const std::string CFG_FORWARDER = "forwarder";

void detectWDCallback(Forwarder *ptr)
{
    ptr->wdCount++;
    NFD_LOG_DEBUG("detectWDCallback");
    if(ptr->numOfInterest.empty())
    {
        NFD_LOG_DEBUG("numOfInterest is empty");
        return;
    }
    //统计numOfInterest占的比例
    std::map<uint64_t, double> ratioOfInterest;
    //输入到文件(默认模式），第一行为seq ratio,以tab键分隔
    std::ofstream outfile("/media/sf_ndnsim/node" + std::to_string(ptr->mynodeid) + "period" + std::to_string(ptr->wdCount) + " seq.txt");
    if (outfile.is_open()) {
        outfile << "seq" << "\t" << "ratioOfInterest" << "\n";
        for (auto it = ptr->numOfInterest.begin(); it != ptr->numOfInterest.end(); it++) {
            ratioOfInterest[it->first] = it->second / double(ptr->totalInterest);
            outfile << it->first << "\t" << ratioOfInterest[it->first] << "\n";
        }
        outfile.close();
        std::cout << "数据已保存到文件: " << "/media/sf_ndnsim/node" + std::to_string(ptr->mynodeid) + "period" + std::to_string(ptr->wdCount) + " seq.txt" << std::endl;
    } else {
        std::cerr << "无法打开文件: " << "/media/sf_ndnsim/node" + std::to_string(ptr->mynodeid) + "period" + std::to_string(ptr->wdCount) + " seq.txt" << std::endl;
    }
    //统计intervalSeriesOfInterest的均值
    std::map<uint64_t, int> avgIntervalOfInterest;
    std::ofstream outfile2("/media/sf_ndnsim/node" + std::to_string(ptr->mynodeid) + "period" + std::to_string(ptr->wdCount) + " interval.txt");
    if (outfile2.is_open()) {
        outfile2 << "seq" << "\t" << "avgInterval" << "\n";
        int maxavgInterval = 0;
        for (auto it = ptr->intervalSeriesOfInterest.begin(); it != ptr->intervalSeriesOfInterest.end(); it++) {
            if (it->second.size() == 0) {
                continue;
            }
            int sum = 0;
            for (auto it2 = it->second.begin(); it2 != it->second.end(); it2++) {
                sum += *it2;
            }
            avgIntervalOfInterest[it->first] = sum / it->second.size();
            outfile2 << it->first << "\t" << avgIntervalOfInterest[it->first] << "\n";
            maxavgInterval = std::max(maxavgInterval, avgIntervalOfInterest[it->first]);
        }
        NFD_LOG_DEBUG("maxavgInterval= " << maxavgInterval);
        outfile2 << "maxavgInterval= " << maxavgInterval << "\n";

        // 对于 intervalSeriesOfInterest 为空的 seq，将其均值取为 maxavgInterval 到 watchdogPeriod 之间的随机值
        for (auto it = ptr->intervalSeriesOfInterest.begin(); it != ptr->intervalSeriesOfInterest.end(); it++) {
            if (it->second.size() == 0) {
                avgIntervalOfInterest[it->first] = maxavgInterval + rand() % (ptr->watchdogPeriod.GetMicroSeconds() - maxavgInterval);
                outfile2 << it->first << "\t" << avgIntervalOfInterest[it->first] << "\n";
                // NFD_LOG_DEBUG("seq= " << it->first << " avgInterval= " << avgIntervalOfInterest[it->first]);
            }
        }
        outfile2.close();
        std::cout << "数据已保存到文件: " << "/media/sf_ndnsim/node" + std::to_string(ptr->mynodeid) + "period" + std::to_string(ptr->wdCount) + " interval.txt" << std::endl;
    } else {
        std::cerr << "无法打开文件: " << "/media/sf_ndnsim/node" + std::to_string(ptr->mynodeid) + "period" + std::to_string(ptr->wdCount) + " interval.txt" << std::endl;
    }

    // 聚类
    // seq，avgIntervalOfInterest，ratioOfInterest构成三元组，进行聚类
    std::vector<std::tuple<uint64_t, int, double>> data;
    for (const auto& item : avgIntervalOfInterest) {
        data.emplace_back(item.first, item.second, ratioOfInterest[item.first]);
    }

    std::map<uint64_t, std::map<uint64_t, double>> epsilon;
    std::map<uint64_t, double> rho, delta;
    std::map<uint64_t, uint64_t> center;
    double dc = 0.0;
    int n = data.size();
    NFD_LOG_DEBUG("n= "<<n);

    // 计算欧几里德距离
    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            uint64_t seq_i = std::get<0>(data[i]);
            uint64_t seq_j = std::get<0>(data[j]);
            epsilon[seq_i][seq_j] = epsilon[seq_j][seq_i] = std::sqrt(
                std::pow(std::get<1>(data[i]) - std::get<1>(data[j]), 2) * ptr->k1 +
                std::pow(std::get<2>(data[i]) - std::get<2>(data[j]), 2) * ptr->k2
            );
            //NFD_LOG_DEBUG("seq1= "<<seq_i<<" seq2= "<<seq_j<<" epsilon= "<<epsilon[seq_i][seq_j]);
        }
    }

    // 计算dc
    std::vector<double> distances;
    for (const auto& item : epsilon) {
        for (const auto& inner_item : item.second) {
            distances.push_back(inner_item.second);
        }
    }
    std::sort(distances.begin(), distances.end());
    dc = distances[distances.size() * 0.02];
    NFD_LOG_DEBUG("dc= "<<dc);

    // 计算ρ
    double maxRho = 0.0;
    double minRho = std::numeric_limits<double>::max();
    for (const auto& item : epsilon) {
        uint64_t seq_i = item.first;
        rho[seq_i] = 0;
        for (const auto& inner_item : item.second) {
            if (inner_item.second < dc) {
                rho[seq_i] += 1;
            }
        }
        maxRho = std::max(maxRho, rho[seq_i]);
        minRho = std::min(minRho, rho[seq_i]);
        NFD_LOG_DEBUG("seq= "<<seq_i<<" rho= "<<rho[seq_i]);
    }

    std::vector<uint64_t> seqs;
    for (const auto& item : data) {
        seqs.push_back(std::get<0>(item));
    }
    std::sort(seqs.begin(), seqs.end(), [&](uint64_t a, uint64_t b) { return rho[a] > rho[b]; });

    // 计算δ
    double maxDelta = 0.0;
    double minDelta = std::numeric_limits<double>::max();
    for (size_t i = 0; i < seqs.size(); ++i) {
        uint64_t seq_i = seqs[i];
        if (rho[seq_i] == maxRho) {
            delta[seq_i] = std::max_element(epsilon[seq_i].begin(), epsilon[seq_i].end(), [](const auto& a, const auto& b) {
                return a.second < b.second;
            })->second;
        } else {
            delta[seq_i] = std::numeric_limits<double>::max();
            for (size_t j = 0; j < i; ++j) {
                uint64_t seq_j = seqs[j];
                if (epsilon[seq_i][seq_j] < delta[seq_i]) {
                    delta[seq_i] = epsilon[seq_i][seq_j];
                }
            }
        }
        NFD_LOG_DEBUG("seq= " << seq_i << " delta= " << delta[seq_i]);
        minDelta = std::min(minDelta, delta[seq_i]);
        maxDelta = std::max(maxDelta, delta[seq_i]);
    }

    // 通过阈值选取 rho与delta都大的点作为聚类中心
    double rho_threshold = (minRho + maxRho) / 5;
    double delta_threshold = (minDelta + maxDelta) / 5;

    NFD_LOG_DEBUG("rho_threshold= "<<rho_threshold<<" delta_threshold= "<<delta_threshold);
    std::vector<uint64_t> centers;
    for (const auto& item : data) {
        uint64_t seq = std::get<0>(item);
        if (rho[seq] * delta[seq] > rho_threshold * delta_threshold) {
            NFD_LOG_DEBUG("seq= "<<seq<<" rho= "<<rho[seq]<<" delta= "<<delta[seq]);
            //if(rho[seq] > rho_threshold  && delta[seq] > delta_threshold){
                centers.push_back(seq);
                NFD_LOG_DEBUG("center= "<<seq);
            //}
        }
    }

    // 聚类标记
    std::map<uint64_t, int> labels;
    for (size_t i = 0; i < centers.size(); ++i) {
        labels[centers[i]] = i;
        NFD_LOG_DEBUG("seq= "<<centers[i]<<" center label= "<<i);
    }


    for (size_t i = 0; i < seqs.size(); ++i) {
        uint64_t seq_i = seqs[i];
        if (labels.find(seq_i) == labels.end()) {
            uint64_t nearest_point = 0;
            double min_dist = std::numeric_limits<double>::max();
            for (size_t j = 0; j < i; ++j) {
                uint64_t seq_j = seqs[j];
                if (epsilon[seq_i][seq_j] < min_dist) {
                    min_dist = epsilon[seq_i][seq_j];
                    nearest_point = seq_j;
                }
            }
            labels[seq_i] = labels[nearest_point];
            NFD_LOG_DEBUG("seq= " << seq_i << " assigned label from seq= " << nearest_point << " label= " << labels[nearest_point]);
        }
    }

    // 可视化
    std::map<int, std::vector<uint64_t>> clusters;
    for (const auto& item : labels) {
        clusters[item.second].push_back(item.first);
    }

    std::vector<double> x, y;
    std::vector<std::string> seqs_str;
    std::vector<std::string> colors = {"red", "blue", "green", "purple", "orange", "brown", "pink", "gray", "olive", "cyan"};
    std::vector<std::string> point_colors;
    for (const auto& d : data) {
        x.push_back(std::get<1>(d));
        y.push_back(std::get<2>(d));
        seqs_str.push_back(std::to_string(std::get<0>(d)));
        point_colors.push_back(colors[labels[std::get<0>(d)] % colors.size()]);
    }
    NFD_LOG_DEBUG("set x y");

    auto start = std::chrono::high_resolution_clock::now();
    // 清除当前图形
    plt::clf();

    // 使用 scatter_colored 函数批量绘制散点
    plt::scatter_colored(x, y, point_colors, 10.0);

    // 添加文本标签
    for (size_t i = 0; i < x.size(); ++i) {
        plt::text(x[i], y[i], seqs_str[i]);
    }
    // for (size_t i = 0; i < x.size(); ++i) {
    //     plt::scatter(std::vector<double>{x[i]}, std::vector<double>{y[i]}, 10.0, {{"color", point_colors[i]}});
    //     plt::text(x[i], y[i], seqs_str[i]);
    // }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    NFD_LOG_DEBUG("scatter time "<<elapsed.count());

    start = std::chrono::high_resolution_clock::now();
    plt::xlabel("avgIntervalOfInterest");
    plt::ylabel("ratioOfInterest");
    plt::save("/media/sf_ndnsim/cluster_node" + std::to_string(ptr->mynodeid) +"period" + std::to_string(ptr->wdCount) + ".png");
    plt::show(false);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    NFD_LOG_DEBUG("plot and save figure time "<<elapsed.count());

    // 保存数据到文件
    std::string filename = "/media/sf_ndnsim/cluster_node" + std::to_string(ptr->mynodeid) +"period" + std::to_string(ptr->wdCount) + ".txt";
    std::ofstream outfile3(filename);
    if (outfile3.is_open()) {
        for (size_t i = 0; i < x.size(); ++i) {
            outfile3 << "seq: "<<seqs_str[i]<<", x: " << x[i] << ", y: " << y[i] << ", label: " << labels[std::get<0>(data[i])] << ", color: " << point_colors[i] << "\n";
        }
        outfile3.close();
        NFD_LOG_DEBUG("数据已保存到文件: " << filename);
    } else {
        NFD_LOG_DEBUG("无法打开文件: " << filename);
    }

    std::vector<uint64_t> popularSeqs;
    std::vector<uint64_t> unpopularSeqs;
    double maxAvgRatio = 0.0;
    int popularCluster = 0;
    for (const auto& cluster : clusters) {
        double avgRatio = 0.0;
        for (const auto& seq : cluster.second) {
            avgRatio += std::get<2>(*std::find_if(data.begin(), data.end(), [&](const auto& d) {
                return std::get<0>(d) == seq;
            }));
        }
        avgRatio /= cluster.second.size();
        if (avgRatio > maxAvgRatio) {
            maxAvgRatio = avgRatio;
            popularCluster = cluster.first;
        }
    }
    popularSeqs = clusters[popularCluster];
    NFD_LOG_DEBUG("popularCluster= "<<popularCluster);
    //求unpopularSeqs
    for (const auto& cluster : clusters) {
        if (cluster.first != popularCluster) {
            unpopularSeqs.insert(unpopularSeqs.end(), cluster.second.begin(), cluster.second.end());
        }
    }

    // 判断攻击
    if (!ptr->prevClusters.empty()) {
        if (clusters.size() == 1) {
            NFD_LOG_DEBUG("LDA detetct");
            for (const auto& seq : ptr->preunPopularSeqs) {
                ptr->malicious.insert(seq);
                NFD_LOG_DEBUG("detetct seq="<<seq<<" is malicious");
            }
        } else {
            double tau = popularSeqs.size();
            double prevTau = ptr->prevPopularSeqs.size();
            double curOmega = tau - prevTau / prevTau;
            NFD_LOG_DEBUG("curOmega= "<<curOmega<<"avgOmega= "<<ptr->avgOmega<<"xi= "<<ptr->avgOmega*5.2)
            if (curOmega > ptr->avgOmega*5.2) {
                NFD_LOG_DEBUG("FLA detetct");
                for (const auto& seq : popularSeqs) {
                    if (std::find(ptr->prevPopularSeqs.begin(), ptr->prevPopularSeqs.end(), seq) == ptr->prevPopularSeqs.end()) {
                        ptr->malicious.insert(seq);
                        NFD_LOG_DEBUG("detect seq="<<seq<<" is malicious");
                    }
                }
            }
            ptr->avgOmega = (ptr->avgOmiga * (ptr->wdCount-1) + std::abs(curOmega)) / double(ptr->wdCount);
            NFD_LOG_DEBUG("nextAvgOmega= "<<ptr->avgOmega);
        }
    }

    ptr->prevClusters = clusters;
    ptr->prevPopularSeqs = popularSeqs;
    ptr->preunPopularSeqs = unpopularSeqs;

    //重置
    ptr->numOfInterest.clear();
    ptr->intervalSeriesOfInterest.clear();
    ptr->totalInterest = 0;

    clusters.clear();
    unpopularSeqs.clear();
    popularSeqs.clear();

    ptr->detectWD.Ping(ptr->watchdogPeriod);
}


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

  SetWatchDog(ns3::MilliSeconds(5000));
}

Forwarder::~Forwarder() = default;

void
Forwarder::SetWatchDog(ns3::Time t)
{
    if (t > ns3::MilliSeconds(0))
    {
        detectWD.Ping(t);
        detectWD.SetFunction(detectWDCallback);
        detectWD.SetArguments<Forwarder *>(this);
    }
}

void
Forwarder::onIncomingInterest(const Interest& interest, const FaceEndpoint& ingress)
{
  // receive Interest
  NFD_LOG_DEBUG("onIncomingInterest in=" << ingress << " interest=" << interest.getName());


  NFD_LOG_DEBUG("scheme= "<<ingress.face.getRemoteUri().getScheme());
  //scheme类型有internal(初始建立路径)、appface（消费者节点从应用层获得的）和netdev（网络设备即非消费者节点从其他节点获得的）
  if(ingress.face.getRemoteUri().getScheme() == "netdev")
  {
      //获取seq一定要在判断scheme为非internal之后，否则会出现错误，
            //因为internal类型的兴趣包名形如/localhost/nfd/faces/events/seq=3，按照下面的方法获取seq会出现错误，
                //而且不会对该函数报错，而是仍然运行成功，但是log显示兴趣包转发不出去
      auto seq = interest.getName().get(1).toSequenceNumber();
      if(malicious.find(seq) !=malicious.end())
      {
          NFD_LOG_DEBUG("receive seq="<<seq<<" is malicious, drop the interest");
          return;
      }

      totalInterest++;
      //统计seq的数目到numOfInterest
      if(numOfInterest.find(seq) == numOfInterest.end())
      {
          numOfInterest[seq] = 1;
      }
      else
      {
          numOfInterest[seq]++;
      }

      //统计相同seq之间的时间间隔到intervalSeriesOfInterest
      if(intervalSeriesOfInterest.find(seq) == intervalSeriesOfInterest.end())
      {
          intervalSeriesOfInterest[seq] = std::vector<int64_t>();
      }
      else
      {
          intervalSeriesOfInterest[seq].push_back((ns3::Simulator::Now()-lastInterestTime[seq]).GetMicroSeconds());
      }
      lastInterestTime[seq] = ns3::Simulator::Now();


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

} // namespace nfd

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

void detectWDCallback(Forwarder *ptr)
{
    NFD_LOG_DEBUG("detectWDCallback");
    if(ptr->edgeId.find(ptr->mynodeid)!=ptr->edgeId.end())
    {
        if(ptr->nowIntervalSeriesOfFace.empty())
        {
            NFD_LOG_DEBUG("nowIntervalSeriesOfFace is empty");
        }
        else
        {
            ptr->lastIntervalSeriesOfFace=ptr->nowIntervalSeriesOfFace;
            ptr->lastContentSeriesOfFace=ptr->nowContentSeriesOfFace;
            ptr->nowIntervalSeriesOfFace.clear();
            ptr->nowContentSeriesOfFace.clear();

            NFD_LOG_DEBUG("before pre-processing data");
            //打印lastIntervalSeriesOfFace
            NFD_LOG_DEBUG("lastIntervalSeriesOfFace: ");
            for (const auto& entry : ptr->lastIntervalSeriesOfFace) 
            {
                NFD_LOG_DEBUG("Face ID: " << entry.first);
                std::ostringstream oss;
                for (const auto& val : entry.second) {
                    oss << val << " ";
                }
                NFD_LOG_DEBUG(oss.str());
            }

            //打印lastContentSeriesOfFace
            NFD_LOG_DEBUG("lastContentSeriesOfFace: ");
            for (const auto& entry : ptr->lastContentSeriesOfFace) 
            {
                NFD_LOG_DEBUG("Face ID: " << entry.first);
                std::ostringstream oss;
                for (const uint64_t& content : entry.second) 
                {
                    oss << content << " ";
                }
                NFD_LOG_DEBUG(oss.str());
            }

            //得到当前face所属近邻区域的首个face在当前窗口的首个采样元素到其首个元素的时间间隔，从前到后减去face的interval，直到间隔一致
            NFD_LOG_DEBUG("erase interval from left");
            for (auto& entry : ptr->lastIntervalSeriesOfFace) 
            {
                FaceId faceId = entry.first;
                NFD_LOG_DEBUG("faceid: " << faceId);
                FaceId firstFaceInNearRange = ptr->theFirstFaceInNearRangeOfFace[faceId];
                NFD_LOG_DEBUG("firstFaceInNearRange: " << firstFaceInNearRange);
                NFD_LOG_DEBUG("firstInterestTimeInCurWndOfFace[firstFaceInNearRange]: " << ptr->firstInterestTimeInCurWndOfFace[firstFaceInNearRange]);
                NFD_LOG_DEBUG("firstInterestTimeOfFace[firstFaceInNearRange]: " << ptr->firstInterestTimeOfFace[firstFaceInNearRange]);
                int64_t maxUnSampleInterval = (ptr->firstInterestTimeInCurWndOfFace[firstFaceInNearRange] - ptr->firstInterestTimeOfFace[firstFaceInNearRange]).GetMicroSeconds();
                NFD_LOG_DEBUG("maxUnSampleInterval: " << maxUnSampleInterval);
                NFD_LOG_DEBUG("firstInterestTimeInCurWndOfFace[faceId]: " << ptr->firstInterestTimeInCurWndOfFace[faceId]); 
                NFD_LOG_DEBUG("firstInterestTimeOfFace[faceId]: " << ptr->firstInterestTimeOfFace[faceId]);
                int64_t hasUnSampleInterval = (ptr->firstInterestTimeInCurWndOfFace[faceId] - ptr->firstInterestTimeOfFace[faceId]).GetMicroSeconds();

                for(auto it=entry.second.begin();it!=entry.second.end();)
                {
                    NFD_LOG_DEBUG("hasUnSampleInterval: " << hasUnSampleInterval);
                    if((hasUnSampleInterval>=maxUnSampleInterval)&&(*it!=0))
                    {
                        break;
                    }
                    NFD_LOG_DEBUG("earse interval: " << *it);
                    entry.second.erase(it);
                    ptr->lastContentSeriesOfFace[faceId].erase(ptr->lastContentSeriesOfFace[faceId].begin());
                    it = entry.second.begin();
                    hasUnSampleInterval+=*it;//先删除首个元素，再加上补上来的首个元素
                    ptr->firstInterestTimeInCurWndOfFace[faceId]=ptr->firstInterestTimeInCurWndOfFace[faceId]+ns3::MicroSeconds(*it);
                }
            }
            //从后往前删除
            NFD_LOG_DEBUG("earse interval from right");
            for (auto& entry : ptr->lastIntervalSeriesOfFace) 
            {
              FaceId faceId = entry.first;
              NFD_LOG_DEBUG("faceid: " << faceId);
              FaceId lastFaceInNearRange = ptr->theLastFaceInNearRangeOfFace[faceId];
              NFD_LOG_DEBUG("lastFaceInNearRange: " << lastFaceInNearRange);
              NFD_LOG_DEBUG("firstInterestTimeInCurWndOfFace[lastFaceInNearRange]: " << ptr->firstInterestTimeInCurWndOfFace[lastFaceInNearRange]);
              NFD_LOG_DEBUG("firstInterestTimeInCurWndOfFace[faceId]: " << ptr->firstInterestTimeInCurWndOfFace[faceId]);
              int64_t needDropInterval = (ptr->firstInterestTimeInCurWndOfFace[lastFaceInNearRange] - ptr->firstInterestTimeInCurWndOfFace[faceId]).GetMicroSeconds();
              NFD_LOG_DEBUG("needDropInterval: " << needDropInterval);
              for(auto it = entry.second.end();it!=(entry.second.begin()++);)
              {
                  if(needDropInterval<=0)
                  {
                      break;
                  }
                  --it;
                  NFD_LOG_DEBUG("earse interval: " << *it);
                  needDropInterval-=*it;
                  ptr->lastContentSeriesOfFace[entry.first].erase(ptr->lastContentSeriesOfFace[entry.first].end()-1);
                  it=entry.second.erase(it);
              }
            }

            // 对lastContentSeriesOfFace中每个face对应的contentSeries，出现的元素个数计数
            std::map<FaceId, std::map<uint64_t, int>> contentCount;
            for (const auto& entry : ptr->lastContentSeriesOfFace) {
                FaceId faceId = entry.first;
                for (uint64_t content : entry.second) {
                    contentCount[faceId][content]++;
                }
            }

            // 使用基数排序对个数排序，并删除不常见的元素
            auto radixSort = [](std::vector<std::pair<uint64_t, int>>& vec) {
                int maxVal = 0;
                for (const auto& p : vec) {
                    if (p.second > maxVal) {
                        maxVal = p.second;
                    }
                }

                for (int exp = 1; maxVal / exp > 0; exp *= 10) {
                    std::vector<std::vector<std::pair<uint64_t, int>>> buckets(10);
                    for (const auto& p : vec) {
                        int digit = (p.second / exp) % 10;
                        buckets[digit].push_back(p);
                    }

                    vec.clear();
                    for (int i = 9; i >= 0; --i) {
                        for (const auto& p : buckets[i]) {
                            vec.push_back(p);
                        }
                    }
                }
            };
      
            for (auto& entry : ptr->lastContentSeriesOfFace) {
                FaceId faceId = entry.first;
                std::vector<std::pair<uint64_t, int>> countVector(contentCount[faceId].begin(), contentCount[faceId].end());
                radixSort(countVector);

                int total = entry.second.size();
                int cumulative = 0;
                size_t i = 0;
                for (; i < countVector.size(); ++i) {
                    cumulative += countVector[i].second;
                    if (cumulative >= total * 0.95) {
                        break;
                    }
                }

                std::unordered_set<uint64_t> toKeep;
                for (size_t j = 0; j <= i; ++j) {
                    toKeep.insert(countVector[j].first);
                }

                //计算有效内容范围
                ptr->validRangeOfFace[faceId] = i;
                NFD_LOG_DEBUG("faceId: "<< faceId<<" validRangeOfFace: " << i);

                std::vector<uint64_t> newContentSeries;
                for (uint64_t content : entry.second) {
                    if (toKeep.find(content) != toKeep.end()) {
                        newContentSeries.push_back(content);
                    }
                }
                entry.second = newContentSeries;
            }

            NFD_LOG_DEBUG("after pre-processing data");
            //重新打印lastIntervalSeriesOfFace
            NFD_LOG_DEBUG("lastIntervalSeriesOfFace: ");
            for (const auto& entry : ptr->lastIntervalSeriesOfFace) 
            {
                NFD_LOG_DEBUG("Face ID: " << entry.first);
                std::ostringstream oss;
                for (const int64_t& interval : entry.second) 
                {
                    oss << interval << " ";
                }
                NFD_LOG_DEBUG("  " << oss.str());
            }
            //重新打印lastContentSeriesOfFace
            NFD_LOG_DEBUG("lastContentSeriesOfFace: ");
            for (const auto& entry : ptr->lastContentSeriesOfFace) 
            {
                NFD_LOG_DEBUG("Face ID: " << entry.first);
                std::ostringstream oss;
                for (const uint64_t& content : entry.second) 
                {
                    oss << content << " ";
                }
                NFD_LOG_DEBUG("  " << oss.str());
            }

            //准备SimpleClustering聚类的数据
            std::map<FaceId, size_t> intervalLengths;

            for (const auto& entry : ptr->lastIntervalSeriesOfFace) {
                auto faceId = entry.first;
                const std::vector<int64_t>& intervals = entry.second;
                intervalLengths[faceId] = intervals.size();
            }

            std::vector<std::pair<FaceId, size_t>> data;
            for (const auto& entry : intervalLengths) {
                data.push_back(entry);
            }

            // 开始SimpleClustering聚类
            NFD_LOG_DEBUG("SimpleClustering start: ");
            size_t tau = data.size() / 5; // 10%的face数量作为密度阈值
            NFD_LOG_DEBUG("tau: " << tau);
            size_t xi = 2; // 2为网格步长
            std::map<int, std::vector<FaceId>> clusters = ptr->runSimpleClustering(data, xi, tau); 

            // SimpleClustering聚类结果
            NFD_LOG_DEBUG("SimpleClustering output: ");
            for (const auto& cluster : clusters) 
            {
                NFD_LOG_DEBUG("Simple Cluster: " << cluster.first);
                std::ostringstream oss;
                for (int faceId : cluster.second) {
                    oss << faceId << " ";
                }
                NFD_LOG_DEBUG("  Face IDs: " << oss.str());
            }

            NFD_LOG_DEBUG("LSH start: ");
            for (const auto& cluster : clusters) 
            {
                std::set<FaceId> finalSuspect1InCurrentCluster;
                //在SimpleClustering聚类结果中开始LSH聚类
                if (cluster.second.size() < 2) {
                  continue;
                }
                NFD_LOG_DEBUG("in Simple Cluster: " << cluster.first);
                std::ostringstream oss;
                for (int faceId : cluster.second) {
                    oss << faceId << " ";
                }
                NFD_LOG_DEBUG("  Face IDs: " << oss.str());
                oss.str("");
                oss.clear();

                //只使用当前SimpleCluster中的faceId所对应的lastContentSeriesOfFace中的向量
                std::map<FaceId, std::vector<uint64_t>> contentSeriesInCluster;
                for (int faceId : cluster.second) {
                    contentSeriesInCluster[faceId] = ptr->lastContentSeriesOfFace.at(faceId);
                }
                // 将contentSeries向量转换为布尔矩阵，并保留每列和faceId的对应关系
                std::vector<FaceId> faceIdList;
                std::vector<std::vector<bool>> boolMatrix =ptr->convertToBoolSeries(contentSeriesInCluster, faceIdList);

                //假设两个向量对应位置的比特相等的概率为s，则至少有一个哈系桶同时包含这两个向量的概率为p= 1-（1-s^r）^b
                //p随着b的增大而增大，随着r的增大而减小，随着s的增大而增大，所以r要尽量小，b要尽量大
                //例如s=0.8，b=20，r=5，p=0.9996;s=0.2，b=20，r=5，p=0.0064
                int b = 20; // band数量
                int r = 5;  // 每个band的行数
                std::map<int, std::vector<FaceId>> lshClusters = ptr->minHashLSH(boolMatrix, b, r, faceIdList);

                // LSH聚类结果
                for (const auto& cluster : lshClusters) {
                    NFD_LOG_DEBUG("Cluster ID: " << cluster.first);
                    std::ostringstream oss;
                    for (FaceId faceId : cluster.second) {
                        oss << faceId << " ";
                    }
                    NFD_LOG_DEBUG("  Face IDs: " << oss.str());
                }

                //开始假设检验
                NFD_LOG_DEBUG("hypothesis testing start: ");
                double alpha = 0.05;
                ptr->performTests(lshClusters, ptr->lastIntervalSeriesOfFace, alpha, finalSuspect1InCurrentCluster);
                ptr->finalSuspect1.insert(finalSuspect1InCurrentCluster.begin(), finalSuspect1InCurrentCluster.end());
            }
            NFD_LOG_DEBUG("final suspect 1: ");
            std::ostringstream oss;
            for (FaceId faceId : ptr->finalSuspect1) {
                oss << faceId << " ";
            }

            //第二大部分，根据速率与有效范围的比值做孤立森林检测
            NFD_LOG_DEBUG("Isolation Forest start: ");
            ptr->performIsolationForestDetection(ptr->finalSuspect2);
            NFD_LOG_DEBUG("final suspect 2: ");
            oss.str("");
            oss.clear();
            for (FaceId faceId : ptr->finalSuspect2) {
                oss << faceId << " ";
            }

        }
    }
    ptr->detectWD.Ping(ptr->watchdogPeriod);
}

//函数前面要加上类名Forwarder，但声明不需要，因为已经在类中
std::map<int, std::vector<FaceId>> 
Forwarder::runSimpleClustering(const std::vector<std::pair<FaceId, size_t>>& data, size_t xi, size_t tau)
{
    // 将数据按第二个元素（即坐标）进行排序
    std::vector<std::pair<FaceId, size_t>> sortedData = data;
    std::sort(sortedData.begin(), sortedData.end(), [](const auto& a, const auto& b) {
        return a.second < b.second;
    });

    std::map<int, std::vector<FaceId>> clusters;
    size_t clusterId = 0;
    size_t currentClusterSize = 0;

    for (size_t i = 0; i < sortedData.size(); ++i) {
        if (i == 0 || sortedData[i].second - sortedData[i - 1].second > xi) {
            // 如果当前点与前一个点的距离大于xi，开始一个新的聚类
            if (currentClusterSize >= tau) {
                clusterId++;
            }
            currentClusterSize = 0;
        }
        clusters[clusterId].push_back(sortedData[i].first);
        currentClusterSize++;
    }

    // 如果最后一个聚类的大小小于tau，则移除它
    if (currentClusterSize < tau) {
        clusters.erase(clusterId);
    }

    return clusters;
}

// 将所有contentSeries向量转换为布尔矩阵，并保留每列和faceId的对应关系
std::vector<std::vector<bool>> 
Forwarder::convertToBoolSeries(const std::map<FaceId, std::vector<uint64_t>>& contentSeries, std::vector<FaceId>& faceIdList) {
    std::unordered_set<uint64_t> uniqueContents;
    for (const auto& entry : contentSeries) {
        uniqueContents.insert(entry.second.begin(), entry.second.end());
    }

    std::vector<uint64_t> uniqueContentList(uniqueContents.begin(), uniqueContents.end());
    std::unordered_map<uint64_t, size_t> contentIndex;
    for (size_t i = 0; i < uniqueContentList.size(); ++i) {
        contentIndex[uniqueContentList[i]] = i;
        //NFD_LOG_DEBUG("Content " << uniqueContentList[i] << " index: " << i);
    }

    std::vector<std::vector<bool>> boolMatrix(uniqueContentList.size(), std::vector<bool>(contentSeries.size(), false));
    size_t col = 0;
    for (const auto& entry : contentSeries) {
        faceIdList.push_back(entry.first);
        for (uint64_t content : entry.second) {
            boolMatrix[contentIndex[content]][col] = true;
        }
        ++col;
    }
    //打印布尔矩阵
    NFD_LOG_DEBUG("boolMatrix: ");
    //按列打印
    std::ostringstream oss;
    for(size_t i = 0; i < boolMatrix[0].size(); ++i) {
        for(size_t j = 0; j < boolMatrix.size(); ++j) {
            oss << boolMatrix[j][i];
        }
        NFD_LOG_DEBUG(oss.str());
    }

    return boolMatrix;
}

// 生成签名向量
std::vector<int> 
Forwarder::sigGen(const std::vector<std::vector<bool>>& matrix) {
    std::vector<int> result(matrix[0].size(), -1);
    std::vector<int> seqSet(matrix.size());
    std::iota(seqSet.begin(), seqSet.end(), 0);

    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(seqSet.begin(), seqSet.end(), g);

    size_t count = 0;
    for (int randomSeq : seqSet) {
        for (size_t i = 0; i < matrix[0].size(); ++i) {
            if (matrix[randomSeq][i] && result[i] == -1) {
                result[i] = randomSeq;
                ++count;
            }
        }
        if (count == matrix[0].size()) {
            break;
        }
    }

    return result;
}

// 生成签名矩阵
std::vector<std::vector<int>> 
Forwarder::sigMatrixGen(const std::vector<std::vector<bool>>& inputMatrix, int n) {
    std::vector<std::vector<int>> result;
    for (int i = 0; i < n; ++i) {
        auto sig = sigGen(inputMatrix);
        result.push_back(sig);
        //打印签名矩阵
        NFD_LOG_DEBUG("Signature ");
        std::ostringstream oss;
        for (size_t j = 0; j < sig.size(); ++j) {
            oss << sig[j] << " ";
        }
        NFD_LOG_DEBUG(oss.str());
    }
    return result;
}

// 计算MD5哈希值
std::string 
Forwarder::computeMD5(const std::string& str) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)str.c_str(), str.size(), (unsigned char*)&digest);

    char mdString[33];
    for (int i = 0; i < 16; i++)
        sprintf(&mdString[i * 2], "%02x", (unsigned int)digest[i]);

    return std::string(mdString);
}

std::map<int, std::vector<FaceId>> 
Forwarder::minHashLSH(const std::vector<std::vector<bool>>& inputMatrix, int b, int r, const std::vector<FaceId>& faceIdList) {
    std::unordered_map<std::string, std::vector<FaceId>> hashBuckets;

    int n = b * r;
    std::vector<std::vector<int>> sigMatrix = sigMatrixGen(inputMatrix, n);

    int begin = 0, end = r;
    int count = 0;

    while (end <= n) {
        ++count;
        NFD_LOG_DEBUG("count: " << count);
        for (size_t colNum = 0; colNum < sigMatrix[0].size(); ++colNum) {
            NFD_LOG_DEBUG("colNum: " << colNum);
            std::ostringstream oss;
            for (int i = begin; i < end; ++i) {
                oss << sigMatrix[i][colNum] << ",";
            }
            oss << count;
            NFD_LOG_DEBUG("band: " << oss.str());
            auto md5 = computeMD5(oss.str());
            NFD_LOG_DEBUG("MD5: " << md5);
            std::string tag = md5;

            if (hashBuckets.find(tag) == hashBuckets.end()) {
                hashBuckets[tag] = {faceIdList[colNum]};
            } else {
                hashBuckets[tag].push_back(faceIdList[colNum]);
            }
        }
        begin += r;
        end += r;
    }

    // LSH聚类结果（未合并）
    NFD_LOG_DEBUG("LSH output before merging: ");
    for (const auto& bucket : hashBuckets) {
        NFD_LOG_DEBUG(" LSH Bucket " << bucket.first << ":");
        std::ostringstream oss;
        for (FaceId faceId : bucket.second) {
            oss << faceId << " ";
        }
        NFD_LOG_DEBUG("  Face IDs: " << oss.str());
    }

    // LSH聚类结果中，把存在两个以上元素的bucket筛选出来，对这些bucket，如果包含的元素有交叉，则所在的bucket的所有元素放在一类，输出有多少类，且每类的face是什么
    std::map<int, std::vector<FaceId>> mergedClusters;
    std::map<FaceId, int> faceToCluster;
    int clusterId = 0;

    for (const auto& bucket : hashBuckets) {
        if (bucket.second.size() < 2) {
            continue;
        }

        int currentClusterId = -1;
        for (FaceId faceId : bucket.second) {
            if (faceToCluster.find(faceId) != faceToCluster.end()) {
                currentClusterId = faceToCluster[faceId];
                break;
            }
        }

        if (currentClusterId == -1) {
            currentClusterId = clusterId++;
        }

        for (FaceId faceId : bucket.second) {
            faceToCluster[faceId] = currentClusterId;
            if (std::find(mergedClusters[currentClusterId].begin(), mergedClusters[currentClusterId].end(), faceId) == mergedClusters[currentClusterId].end())
            {
                mergedClusters[currentClusterId].push_back(faceId);
            }
        }
    }

    return mergedClusters;
}

// 计算方差
double 
Forwarder::calculateVariance(const std::vector<int64_t>& data, double mean) {
    double variance = 0.0;
    for (const auto& value : data) {
        variance += (value - mean) * (value - mean);
    }
    return variance / (data.size() - 1);
}

// 计算均值
double 
Forwarder::calculateMean(const std::vector<int64_t>& data) {
    return std::accumulate(data.begin(), data.end(), 0.0) / data.size();
}

// F 检验
bool 
Forwarder::fTest(double var1, double var2, size_t size1, size_t size2, double alpha) {
    NFD_LOG_DEBUG("size1: " << size1 << " size2: " << size2);
    double f = var1 / var2;
    NFD_LOG_DEBUG("F-test value: " << f);

    // 使用 boost 库计算临界值
    boost::math::fisher_f_distribution<double> f_dist(size1 - 1, size2 - 1);
    double lowerCriticalValue = boost::math::quantile(f_dist, alpha / 2);
    double upperCriticalValue = boost::math::quantile(boost::math::complement(f_dist, alpha / 2));

    NFD_LOG_DEBUG("F-test lower critical value: " << lowerCriticalValue);
    NFD_LOG_DEBUG("F-test upper critical value: " << upperCriticalValue);

    return f > lowerCriticalValue && f < upperCriticalValue;
}

// t 检验
bool 
Forwarder::tTest(double mean1, double mean2, double var1, double var2, size_t size1, size_t size2, double alpha) {
    NFD_LOG_DEBUG("size1: " << size1 << " size2: " << size2);
    double sw2 = ((size1 - 1) * var1 + (size2 - 1) * var2) / (size1 + size2 - 2);
    double t = (mean1 - mean2) / std::sqrt(sw2 * (1.0 / size1 + 1.0 / size2));
    NFD_LOG_DEBUG("t-test value: " << t);

    // 使用 boost 库计算临界值
    boost::math::students_t_distribution<double> t_dist(size1 + size2 - 2);
    double criticalValue = boost::math::quantile(boost::math::complement(t_dist, alpha / 2));

    NFD_LOG_DEBUG("t-test critical value: " << criticalValue);

    return std::abs(t) < criticalValue;
}

//假设检验执行
void 
Forwarder::performTests(std::map<int, std::vector<FaceId>>& data, 
                        const std::map<FaceId, std::vector<int64_t>>& lastIntervalSeriesOfFace, 
                        double alpha, std::set<FaceId>& finalSuspect1) {
    std::map<FaceId, std::pair<double, double>> meanVarianceCache; // 缓存均值和方差

    // 预先计算所有 FaceId 的均值和方差
    for (const auto& entry : lastIntervalSeriesOfFace) {
        double mean = calculateMean(entry.second);
        double variance = calculateVariance(entry.second, mean);
        meanVarianceCache[entry.first] = {mean, variance};
    }

    for (auto& cluster : data) {
        NFD_LOG_DEBUG("Cluster " << cluster.first << ": ");
        auto& faceIds = cluster.second;
        bool foundFirstPair = false;
        FaceId referenceFaceId = -1;
        size_t firstIndex = 0;
        size_t secondIndex = 0;

        for (size_t i = 0; i < faceIds.size(); ++i) {
            NFD_LOG_DEBUG("Face " << faceIds[i]);
            //打印intervalSeries
            std::ostringstream oss;
            for (const auto& val : lastIntervalSeriesOfFace.at(faceIds[i])) {
                oss << val << " ";
            }  
            NFD_LOG_DEBUG("  " << oss.str());
            for (size_t j = i + 1; j < faceIds.size(); ++j) {
                NFD_LOG_DEBUG("Face " << faceIds[j]);
                //打印intervalSeries
                oss.str("");
                oss.clear();
                for (const auto& val : lastIntervalSeriesOfFace.at(faceIds[j])) {
                    oss << val << " ";
                }
                NFD_LOG_DEBUG("  " << oss.str());
                const auto& sample1 = lastIntervalSeriesOfFace.at(faceIds[i]);
                const auto& sample2 = lastIntervalSeriesOfFace.at(faceIds[j]);

                double mean1 = meanVarianceCache[faceIds[i]].first;
                double var1 = meanVarianceCache[faceIds[i]].second;
                double mean2 = meanVarianceCache[faceIds[j]].first;
                double var2 = meanVarianceCache[faceIds[j]].second;
                NFD_LOG_DEBUG("mean1: " << mean1 << " var1: " << var1);
                NFD_LOG_DEBUG("mean2: " << mean2 << " var2: " << var2);

                if (fTest(var1, var2, sample1.size(), sample2.size(), alpha)) {
                    if (tTest(mean1, mean2, var1, var2, sample1.size(), sample2.size(), alpha)) {
                        NFD_LOG_DEBUG("Cluster " << cluster.first << ": Face " << faceIds[i] << " and Face " << faceIds[j] << " have equal means and variances.");
                        finalSuspect1.insert(faceIds[i]);
                        finalSuspect1.insert(faceIds[j]);
                        referenceFaceId = faceIds[i];
                        firstIndex = i;
                        secondIndex = j;
                        foundFirstPair = true;
                        NFD_LOG_DEBUG("Cluster " << cluster.first << ": First pair found - Face " << faceIds[i] << " and Face " << faceIds[j] << " have equal means and variances.");
                        break;
                    }
                    else{
                        NFD_LOG_DEBUG("Cluster " << cluster.first << ": Face " << faceIds[i] << " and Face " << faceIds[j] << " do not have equal means.");
                    }
                }
                else{
                    NFD_LOG_DEBUG("Cluster " << cluster.first << ": Face " << faceIds[i] << " and Face " << faceIds[j] << " do not have equal variances.");
                }
            }

            if (foundFirstPair) {
                break;
            }
        }

        if (foundFirstPair) {
            // 只保留 j+1 之后 的 face
            NFD_LOG_DEBUG("referenceFaceId: " << referenceFaceId);
            for (size_t i = secondIndex+1; i < faceIds.size(); ++i) {
                NFD_LOG_DEBUG("Face " << faceIds[i]);
                const auto& sample1 = lastIntervalSeriesOfFace.at(referenceFaceId);
                const auto& sample2 = lastIntervalSeriesOfFace.at(faceIds[i]);

                double mean1 = meanVarianceCache[referenceFaceId].first;
                double var1 = meanVarianceCache[referenceFaceId].second;
                double mean2 = meanVarianceCache[faceIds[i]].first;
                double var2 = meanVarianceCache[faceIds[i]].second;

                if (fTest(var1, var2, sample1.size(), sample2.size(), alpha)) {
                    if (tTest(mean1, mean2, var1, var2, sample1.size(), sample2.size(), alpha)) {
                        finalSuspect1.insert(faceIds[i]);
                        NFD_LOG_DEBUG("Cluster " << cluster.first << ": Face " << referenceFaceId << " and Face " << faceIds[i] << " have equal means and variances.");
                    } else {
                        NFD_LOG_DEBUG("Cluster " << cluster.first << ": Face " << referenceFaceId << " and Face " << faceIds[i] << " do not have equal means.");
                    }
                } else {
                    NFD_LOG_DEBUG("Cluster " << cluster.first << ": Face " << referenceFaceId << " and Face " << faceIds[i] << " do not have equal variances.");
                }
            }
        }
    }

    NFD_LOG_DEBUG("Final Suspect1 Faces: ");
    for (const auto& faceId : finalSuspect1) {
        NFD_LOG_DEBUG(faceId);
    }
}

void 
Forwarder::performIsolationForestDetection(std::set<FaceId>& finalSuspect2) {
    // 准备输入数据
    Json::Value inputData;
    for (const auto& entry : lastIntervalSeriesOfFace) {
        FaceId faceId = entry.first;
        double validRange = validRangeOfFace[faceId];
        double length = entry.second.size();
        double feature = length / validRange;
        NFD_LOG_DEBUG("Face " << faceId << " validRange: " << validRange << " length: " << length << " feature: " << feature);
        inputData[std::to_string(faceId)] = feature;
    }

    // 写入到临时文件
    std::ofstream inputFile("input.json");
    inputFile << inputData;
    inputFile.close();

    // 调用 Python 脚本
    std::string command = "python3 isolation_forest.py < input.json > output.json";
    std::system(command.c_str());

    // 读取输出结果
    std::ifstream outputFile("output.json");
    Json::Value outputData;
    outputFile >> outputData;
    outputFile.close();

    // 处理检测结果
    double anomaly_threshold = -0.2; // 设定异常分数阈值
    for (const auto& faceId : outputData.getMemberNames()) {
        const Json::Value& result = outputData[faceId];
        int prediction = result["prediction"].asInt();
        double anomaly_score = result["anomaly_score"].asDouble();
        NFD_LOG_DEBUG("Face " << faceId << " prediction: " << prediction << " anomaly_score: " << anomaly_score);
        if (anomaly_score < anomaly_threshold) {
            finalSuspect2.insert(std::stoi(faceId));
        }
    }
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
  , curStartTime(ns3::Seconds(0))
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

  SetWatchDog(ns3::MilliSeconds(1000));
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
      NFD_LOG_DEBUG("seq= "<<seq);
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
      if(edgeId.find(mynodeid)!=edgeId.end())
      {
        //第一个包
        if(hasInterestOfFace.find(faceId)==hasInterestOfFace.end())
        {
          NFD_LOG_DEBUG("first interest of face");
          hasInterestOfFace[faceId]=true;
          lastInterestTimeOfFace[faceId]=ns3::Simulator::Now();
          NFD_LOG_DEBUG("lastInterestTimeOfFace= "<<lastInterestTimeOfFace[faceId]); 
          if(curStartTime==ns3::Seconds(0))
          {
            NFD_LOG_DEBUG("curStartTime=0");
            curStartTime=ns3::Simulator::Now();
            curFirstFaceInNearRange=faceId;
            theFirstFaceInNearRangeOfFace[faceId]=curFirstFaceInNearRange;
          }
          else{
            NFD_LOG_DEBUG("curStartTime!=0");
            //如果当前时间与当前范围内的首次请求的时刻的时间间隔小于最大可接受延迟，则视为同一范围，设置相对延迟
            if((ns3::Simulator::Now()-curStartTime).GetMicroSeconds() <= maxAcceptableDelay)
            {
              NFD_LOG_DEBUG("curStartTime!=0 and within maxAcceptableDelay");
              theFirstFaceInNearRangeOfFace[faceId]=curFirstFaceInNearRange;
              curLastFaceInNearRange=faceId;
              //theLastFaceInNearRangeOfFace未初始化的，置为当前face
              NFD_LOG_DEBUG("update earlier face's theLastFaceInNearRangeOfFace");
              for(auto it=theFirstFaceInNearRangeOfFace.begin();it!=theFirstFaceInNearRangeOfFace.end();it++)
              {
                NFD_LOG_DEBUG("faceId= "<<it->first);
                if(it->second==theFirstFaceInNearRangeOfFace[faceId])
                {
                    theLastFaceInNearRangeOfFace[it->first]=curLastFaceInNearRange;
                }
                NFD_LOG_DEBUG("theLastFaceInNearRangeOfFace= "<<theLastFaceInNearRangeOfFace[it->first]);
              }
            }
            //否则，开启新的范围，将当前时间作为新的范围内的首次请求的时刻
            else
            {
              NFD_LOG_DEBUG("curStartTime!=0 and beyond maxAcceptableDelay"); 
              curStartTime=ns3::Simulator::Now();
              curFirstFaceInNearRange=faceId;
              theFirstFaceInNearRangeOfFace[faceId]=curFirstFaceInNearRange;
              // relativeDelayToCurStartOfFace[faceId]=0;
              // maxDelayToCurStartOfFace[faceId]=0;
            }
          }
          NFD_LOG_DEBUG("curStartTime= "<<curStartTime);
        }
        //非第一个包
        else
        {
          //第二个包
          if(firstInterestTimeOfFace.find(faceId)==firstInterestTimeOfFace.end())
          {
            firstInterestTimeOfFace[faceId]=ns3::Simulator::Now();
            NFD_LOG_DEBUG("firstInterestTimeOfFace= "<<firstInterestTimeOfFace[faceId]); 
          }
          //第三个包及以后
          if(nowIntervalSeriesOfFace.find(faceId)!=nowIntervalSeriesOfFace.end()){
            NFD_LOG_DEBUG("something exists in nowIntervalSeriesOfFace");
            int64_t interval = (ns3::Simulator::Now()-lastInterestTimeOfFace[faceId]).GetMicroSeconds();
            nowContentSeriesOfFace[faceId].push_back(seq);
            nowIntervalSeriesOfFace[faceId].push_back(interval);
            lastInterestTimeOfFace[faceId]=ns3::Simulator::Now();
          }
          //第二个包或后续窗口的第一个包，第一次取到interval
          else{
            NFD_LOG_DEBUG("nothing exists in nowIntervalSeriesOfFace");
            int64_t interval = (ns3::Simulator::Now()-lastInterestTimeOfFace[faceId]).GetMicroSeconds();
            nowContentSeriesOfFace[faceId]=std::vector<FaceId>{seq};
            nowIntervalSeriesOfFace[faceId]=std::vector<int64_t>{interval};
            firstInterestTimeInCurWndOfFace[faceId]=ns3::Simulator::Now();
            NFD_LOG_DEBUG("firstInterestTimeInCurWndOfFace= "<<firstInterestTimeInCurWndOfFace[faceId]);
            lastInterestTimeOfFace[faceId]=ns3::Simulator::Now();
          }
        }
        //必须加个判断条件才能打印，否则直接打印的话会使用map[key]，这个语句会直接插入key
        // if(nowIntervalSeriesOfFace.find(faceId)!=nowIntervalSeriesOfFace.end()){
        //   NFD_LOG_DEBUG("nowIntervalSeriesOfFace: ");
        //   for (auto it = nowIntervalSeriesOfFace[faceId].begin(); it != nowIntervalSeriesOfFace[faceId].end(); ++it) {
        //     NFD_LOG_DEBUG("interval = "<<*it);
        //   }
        //   NFD_LOG_DEBUG("nowContentSeriesOfFace: ");
        //   for (auto it = nowContentSeriesOfFace[faceId].begin(); it != nowContentSeriesOfFace[faceId].end(); ++it) {
        //     NFD_LOG_DEBUG("content = "<<*it);
        //   }
        // }
      }
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

  // CS insert
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

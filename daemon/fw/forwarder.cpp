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

#include "face/null-face.hpp"
#include <cmath>

namespace nfd {

NFD_LOG_INIT(Forwarder);

const std::string CFG_FORWARDER = "forwarder";

void computePITWDCallback(Forwarder *ptr)
{   
    ptr->timePitSeries++;
    ptr->timeDelaySeries++;
    ptr->count++;
    ptr->countSmallPeriod++;
    // if(ptr->curPit.empty()){
    //   NFD_LOG_DEBUG("curPit is empty");
    // }
    for(const auto& pair: ptr->curPit){
        if(ptr->pitSeries.find(pair.first)!=ptr->pitSeries.end()){//每50ms采样pit到pitSeries
            if(ptr->maliciousPrefix.find(pair.first)!=ptr->maliciousPrefix.end()){
              //NFD_LOG_DEBUG("prefix: "<<pair.first<<" pit: "<<pair.second);
            }
            ptr->pitSeries[pair.first].push(pair.second);
            if(ptr->pitSeries[pair.first].size()>10){//pitSeries保存10个历史值
                ptr->pitSeries[pair.first].pop();
            }
        }
        else{
            ptr->pitSeries[pair.first] = std::queue<int>();
            ptr->pitSeries[pair.first].push(0);
        }
    }
    // ptr->totalPitSeries.push(ptr->totalPit);
    // if(ptr->totalPitSeries.size()>10){//pitSeries保存10个历史值
    //     ptr->totalPitSeries.pop();
    // }

    if(ptr->timeDelaySeries==10){//每500ms求delay平均值
    //     std::queue<int> tempTotalPit=ptr->totalPitSeries;
    //     auto sum3=0;
    //     while (!tempTotalPit.empty()) {
    //         sum3 += tempTotalPit.front();  // 累加队首元素
    //         tempTotalPit.pop();  // 移除队首元素
    //     }
    //     ptr->avgTotalPit = sum3 / ptr->totalPitSeries.size();

        ptr->avgTotalDelay=ns3::NanoSeconds(0);
        for(const auto& pair: ptr->pitSeries){//不用delaySeries而用pitSeries，因为2s后才有数据返回，才有delaySeries
            NFD_LOG_DEBUG("prefix: "<<pair.first);
            //delaySeries为空
            if(ptr->delaySeries.find(pair.first)==ptr->delaySeries.end()){
              NFD_LOG_DEBUG("delaySeries has no");
              if(ptr->numDropInterest[pair.first]!=0){
                auto sum2=ns3::Seconds(2);
                ptr->numDropInterest[pair.first]=0;
                NFD_LOG_DEBUG("average delay "<<pair.first<<" "<<sum2);
                if(ptr->avgDelay.find(pair.first)!=ptr->avgDelay.end()){
                    double deltaRate;
                    if(ptr->avgDelay[pair.first]!=ns3::NanoSeconds(0)){
                      deltaRate=(sum2-ptr->avgDelay[pair.first]).GetDouble() / ptr->avgDelay[pair.first].GetDouble();
                    }
                    else if(sum2==ns3::NanoSeconds(0)){
                      deltaRate=0;
                    }
                    else{
                      deltaRate=1;
                    }
                    ptr->deltaRateDelay[pair.first]=deltaRate;
                    NFD_LOG_DEBUG("delta rate delay "<<deltaRate);
                }
                ptr->avgDelay[pair.first]=sum2;          
                ptr->avgTotalDelay = ptr->avgTotalDelay+sum2;
              }
            }
            if(ptr->delaySeries.find(pair.first)!=ptr->delaySeries.end()){
                auto sum2=ns3::Simulator::Now()-ns3::Simulator::Now();
                //NFD_LOG_DEBUG("delaySeries: " );
                for (auto num : ptr->delaySeries[pair.first]) {
                    //NFD_LOG_DEBUG(num<<" ");
                    sum2 += num;
                }
                if(ptr->delaySeries[pair.first].size()==0){//delaySeries有pair.first这个key，但是对应的value是个vector，可能为空
                  NFD_LOG_DEBUG("delaySeries empty");
                  sum2=ns3::Seconds(2);
                }
                else{
                  // auto noreply = ptr->numInterest[pair.first] - ptr->numData[pair.first];
                  // sum2 = sum2 + noreply * ns3::Seconds(2);
                  // NFD_LOG_DEBUG("delaySeries size"<<ptr->delaySeries[pair.first].size());
                  // NFD_LOG_DEBUG("noreply"<<noreply);
                  // sum2 = sum2 / (ptr->delaySeries[pair.first].size() + noreply);
                  sum2 = sum2 + ptr->numDropInterest[pair.first]*ns3::Seconds(2);
                  sum2 = sum2 / (ptr->delaySeries[pair.first].size() + ptr->numDropInterest[pair.first]);
                  //sum2 = sum2 / ptr->delaySeries[pair.first].size();
                }
                ptr->numDropInterest[pair.first]=0;
                NFD_LOG_DEBUG("average delay "<<pair.first<<" "<<sum2);
                ptr->delaySeries[pair.first].clear();
                if(ptr->avgDelay.find(pair.first)!=ptr->avgDelay.end()){
                    double deltaRate;
                    if(ptr->avgDelay[pair.first]!=ns3::NanoSeconds(0)){
                      deltaRate=(sum2-ptr->avgDelay[pair.first]).GetDouble() / ptr->avgDelay[pair.first].GetDouble();
                    }
                    else if(sum2==ns3::NanoSeconds(0)){
                      deltaRate=0;
                    }
                    else{
                      deltaRate=1;
                    }
                    ptr->deltaRateDelay[pair.first]=deltaRate;
                    NFD_LOG_DEBUG("delta rate delay "<<deltaRate);
                }
                ptr->avgDelay[pair.first]=sum2;          
                ptr->avgTotalDelay = ptr->avgTotalDelay+sum2;
            } 
        }
        ptr->timeDelaySeries=0; 
    }

    if(ptr->timePitSeries==10){//每500ms求一次pit平均值
        //ptr->curMaliciousPrefix.clear();
        //ptr->curSuspectPrefix.clear();
        ptr->avgTotalPit=0;
        for(const auto& pair: ptr->pitSeries){
            NFD_LOG_DEBUG("numData "<<ptr->numData[pair.first]);
            if(ptr->numData[pair.first]==0){
              if(ptr->noData.find(pair.first)!=ptr->noData.end()){
                ptr->noData[pair.first]++;
              }
              else{
                ptr->noData[pair.first]=1;
              }
            }
            else{
              ptr->noData[pair.first]=0;
            }
            NFD_LOG_DEBUG("noData "<<ptr->noData[pair.first]);
            if(ptr->noData[pair.first]==20){//2s没有数据到来，则清空pit
              NFD_LOG_DEBUG("curPit "<<ptr->curPit[pair.first]);
              ptr->totalPit=ptr->totalPit - ptr->curPit[pair.first] - ptr->curUnallocPit+7;
              ptr->curPit[pair.first]=0;
              ptr->curUnallocPit=0;
              while(!ptr->pitSeries[pair.first].empty()){
                    ptr->pitSeries[pair.first].pop();
              }
              //ptr->noData[pair.first]=0;
            }
            NFD_LOG_DEBUG("prefix: "<<pair.first);
            float sum = 0;
            //NFD_LOG_DEBUG("输出pitSeries: " );
            std::queue<int>  tempQueue = ptr->pitSeries[pair.first];
            while (!tempQueue.empty()) {
                //NFD_LOG_DEBUG(tempQueue.front()<<" ");
                sum += tempQueue.front();  // 累加队首元素
                tempQueue.pop();  // 移除队首元素
            }
            sum=sum/float(10);
            ptr->avgPit[pair.first]=sum;
            NFD_LOG_DEBUG("average pit "<<pair.first<<" "<<sum);
            int temp;
            if(ptr->deltaRateDelay.find(pair.first)!=ptr->deltaRateDelay.end()){
              temp = ptr->avgPit[pair.first] * (1 + ptr->deltaRateDelay[pair.first]);
            }
            else{
              temp = ptr->avgPit[pair.first];
            }
            if(ptr->allocPit.find(pair.first)==ptr->allocPit.end()){
              ptr->allocPit[pair.first]=ptr->minAllocPit;
            }
            int nowRate = ptr->numInterest[pair.first] *(ns3::Seconds(1).GetMilliSeconds()/(ptr->watchdogPeriod.GetMilliSeconds()*10));
            if(ptr->mynodeid==ptr->BTNkId){
              if(nowRate > std::max(ptr->rate[pair.first], ptr->minAcceptRate) * ptr->tao)//添加可疑前缀
              {
                  NFD_LOG_DEBUG("suspectPrefix "<<pair.first);
                  ptr->suspectPrefix.insert(pair.first);
                  NFD_LOG_DEBUG("unallocPitCapacity "<<ptr->unallocPitCapacity);
                  NFD_LOG_DEBUG("alloc pit "<<ptr->allocPit[pair.first]);
                  NFD_LOG_DEBUG("rate "<<pair.first<<" "<<nowRate);
              }
              else{//非可疑前缀才动态分配pit空间
                ptr->unallocPitCapacity = ptr->unallocPitCapacity + ptr->allocPit[pair.first] - std::max(temp, ptr->minAllocPit);//更新unallocPitCapacity
                ptr->allocPit[pair.first] = std::max(temp, ptr->minAllocPit);//更新allocPit
                NFD_LOG_DEBUG("unallocPitCapacity "<<ptr->unallocPitCapacity);
                NFD_LOG_DEBUG("alloc pit "<<ptr->allocPit[pair.first]);
                NFD_LOG_DEBUG("rate "<<pair.first<<" "<<nowRate);
              }
            }
            ptr->rate[pair.first] = nowRate;//更新当前rate(不管是不是可疑前缀)
            ptr->numInterest[pair.first]=0;
            ptr->numData[pair.first]=0;
            ptr->avgTotalPit=ptr->avgTotalPit+ptr->avgPit[pair.first];
        }
        NFD_LOG_DEBUG("totalPit: "<<ptr->avgTotalPit + ptr->curUnallocPit);
        NFD_LOG_DEBUG("straight totalPit: "<<ptr->totalPit);
        if(ptr->mynodeid==ptr->BTNkId){
          //添加恶意前缀
          for (auto element : ptr->suspectPrefix) {
              NFD_LOG_DEBUG(element);
              NFD_LOG_DEBUG("avgDelay "<<ptr->avgDelay[element]);
              if(ptr->avgDelay[element] > ptr->DH){
                NFD_LOG_DEBUG("maliciousPrefix "<<element);
                //ptr->curMaliciousPrefix.insert(element);
                ptr->maliciousPrefix.insert(element);
              }
          }
          //计算波动因子
          if(ptr->suspectPrefix.size()!=0){
            auto maliRate = double(ptr->maliciousPrefix.size()) / double(ptr->suspectPrefix.size());
            // if(maliRate<0.9){
            //   ptr->tao = ptr->tao + maliRate;
            // }
            // else{
            //   ptr->tao = std::min(ptr->tao - maliRate, 1.5);
            // }
            if(maliRate==0){
              ptr->tao=10;
            }
            else{
              ptr->tao = 1- log(maliRate)/log(1.3);
            }
            NFD_LOG_DEBUG("mailiRate "<<maliRate);
            NFD_LOG_DEBUG("tao "<<ptr->tao);
          }
        }
        //计算总平均延迟(应该最后计算，使得判断恶意前缀时使用的是上一周期的DH)
        if(ptr->avgDelay.size()!=0){
          ptr->avgTotalDelay = ptr->avgTotalDelay / ptr->avgDelay.size();
          NFD_LOG_DEBUG("average total delay "<<ptr->avgTotalDelay);
          NFD_LOG_DEBUG("0.8PitTimeout "<<ptr->PitTimeout*4/5);
          ptr->DH = ns3::Min(ptr->m * ptr->avgTotalDelay, ptr->PitTimeout*4/5);
          NFD_LOG_DEBUG("DH "<<ptr->DH);
        }

        ptr->timePitSeries=0;
    }


  NFD_LOG_DEBUG("ptr->mynodeid "<<ptr->mynodeid<<(ptr->edgeId.find(ptr->mynodeid)!=ptr->edgeId.end()));
  //先判断是否到达周期，再判断是否是边缘，因为pcon等算法在1s后才发兴趣包，所以边缘在1s后才收到兴趣包才确定自己的nodeid,这个时候如果后判断是否到达周期，则会使得1.05s时countSmallPeriod=21，无法进入
    if(ptr->countSmallPeriod==10){//每500ms小周期统计一次face的delay平均值
      if(ptr->edgeId.find(ptr->mynodeid)!=ptr->edgeId.end()){//边缘节点
        for(const auto& pair: ptr->delaySeriesOfFace){
            NFD_LOG_DEBUG(pair.first);
            if(ptr->delaySeriesOfFace.find(pair.first)==ptr->delaySeriesOfFace.end()){
              NFD_LOG_DEBUG("delaySeriesOfFace has no");
            }
            else{
                auto sum2=ns3::Simulator::Now()-ns3::Simulator::Now();
                for (auto num : ptr->delaySeriesOfFace[pair.first]) {
                    sum2 += num;
                }
                if(ptr->delaySeriesOfFace[pair.first].size()==0){//delaySeries有pair.first这个key，但是对应的value是个vector，可能为空
                  NFD_LOG_DEBUG("delaySeriesOfFace empty");
                }
                else{
                  sum2 = sum2 + ptr->numDropInterestOfFace[pair.first]*ns3::Seconds(2);
                  sum2 = sum2 / (ptr->delaySeriesOfFace[pair.first].size() + ptr->numDropInterestOfFace[pair.first]);
                  //sum2 = sum2 / ptr->delaySeries[pair.first].size();
                }
                NFD_LOG_DEBUG("avgDelaySeriesOfFace "<<sum2);
                ptr->numDropInterestOfFace[pair.first]=0;
                ptr->delaySeriesOfFace[pair.first].clear();
                //小周期统计端口平均delay
                if(ptr->avgDelaySeriesOfFace.find(pair.first)!=ptr->avgDelaySeriesOfFace.end()){
                    ptr->avgDelaySeriesOfFace[pair.first].push_back(sum2);
                }
                else{
                    ptr->avgDelaySeriesOfFace[pair.first] = std::vector<ns3::Time>();
                    ptr->avgDelaySeriesOfFace[pair.first].push_back(sum2);
                }
            } 
        }
      } 
      ptr->countSmallPeriod=0; 
    }

  if(ptr->count==100){//每5s大周期统计一次face的delay平均值、rate平均值、恶意请求比例
    if(ptr->edgeId.find(ptr->mynodeid)!=ptr->edgeId.end()){//边缘节点
      for(const auto& pair: ptr->numInterestOfFace){
        NFD_LOG_DEBUG(pair.first);
        //端口速率
        ptr->rateOfFace[pair.first] = ptr->numInterestOfFace[pair.first] *(double(ns3::Seconds(1).GetMilliSeconds())/(double(ptr->watchdogPeriod.GetMilliSeconds()*100)));
        NFD_LOG_DEBUG("rateOfFace "<<pair.first<<" "<<ptr->rateOfFace[pair.first]);
        ptr->avgRateOfAllFace += ptr->rateOfFace[pair.first];
        //端口恶意请求比例
        if(ptr->malirateOfFace.find(pair.first)==ptr->malirateOfFace.end()){
            ptr->malirateOfFace[pair.first]=0;
        }
        for(const auto& pair2: ptr->maliciousPrefix){
          if(ptr->numInterestOfFacePrefix.find(std::make_pair(pair.first, pair2))!=ptr->numInterestOfFacePrefix.end()){
            ptr->malirateOfFace[pair.first] += ptr->numInterestOfFacePrefix[std::make_pair(pair.first, pair2)];
          }
          ptr->numInterestOfFacePrefix[std::make_pair(pair.first, pair2)]=0;
        }
        ptr->malirateOfFace[pair.first] /= double(ptr->numInterestOfFace[pair.first]);
        NFD_LOG_DEBUG("malirateOfFace "<<ptr->malirateOfFace[pair.first]);
        ptr->numInterestOfFace[pair.first]=0;
      } 
      ptr->avgRateOfAllFace = ptr->avgRateOfAllFace / ptr->rateOfFace.size();
      NFD_LOG_DEBUG("avgRateOfAllFace "<<ptr->avgRateOfAllFace);
      //端口rtt
      for(const auto& pair: ptr->avgDelaySeriesOfFace){
        NFD_LOG_DEBUG(pair.first);
        if(ptr->avgDelaySeriesOfFace.find(pair.first)==ptr->avgDelaySeriesOfFace.end()){
          NFD_LOG_DEBUG("avgDelaySeriesOfFace has no");
        }
        else{
            auto sum2=ns3::Simulator::Now()-ns3::Simulator::Now();
            for (auto num : ptr->avgDelaySeriesOfFace[pair.first]) {
                sum2 += num;
            }
            if(ptr->avgDelaySeriesOfFace[pair.first].size()==0){
              NFD_LOG_DEBUG("avgDelaySeriesOfFace empty");
            }
            else{
              sum2 = sum2 / (ptr->avgDelaySeriesOfFace[pair.first].size());
            }
            ptr->avgDelayOfFace[pair.first]=sum2;
            NFD_LOG_DEBUG("avgDelayOfFace "<<pair.first<<" "<<ptr->avgDelayOfFace[pair.first]);
            ptr->avgDelaySeriesOfFace[pair.first].clear();
        } 
      }
      for(const auto& pair4: ptr->avgDelayOfFace){
          ptr->avgDelayOfAllFace += ptr->avgDelayOfFace[pair4.first];
      }
      NFD_LOG_DEBUG("avgDelayOfFace.size: "<<ptr->avgDelayOfFace.size());
      ptr->avgDelayOfAllFace = ptr->avgDelayOfAllFace / ptr->avgDelayOfFace.size();
      NFD_LOG_DEBUG("avgDelayOfAllFace "<<ptr->avgDelayOfAllFace);
      //确定恶意端口
      for(const auto& pair5: ptr->avgDelaySeriesOfFace){
        if(ptr->malirateOfFace[pair5.first]>0.5||ptr->avgDelayOfFace[pair5.first]>2*ptr->avgDelayOfAllFace||ptr->rateOfFace[pair5.first]>2*ptr->avgRateOfAllFace){
          NFD_LOG_DEBUG("malicious face: "<<pair5.first);
          ptr->maliciousFace.insert(pair5.first);
        }
      }
      ptr->count=0;
    }
  }
    

  ptr->computePITWD.Ping(ptr->watchdogPeriod);
  //ptr->computePITWD.Ping(ns3::MilliSeconds(50));
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
  
   SetWatchDog(ns3::MilliSeconds(50));
  //SetWatchDog(50);
}

Forwarder::~Forwarder() = default;

void 
Forwarder::SetWatchDog(ns3::Time t)
{
    if (t > ns3::MilliSeconds(0))
    {
        computePITWD.Ping(t);
        computePITWD.SetFunction(computePITWDCallback);
        computePITWD.SetArguments<Forwarder *>(this);
    }
}

// void 
// Forwarder::SetWatchDog(double t)
// {
//     if (t > 0)
//     {
//         computePITWD.Ping(ns3::MilliSeconds(t));
//         computePITWD.SetFunction(computePITWDCallback);
//         computePITWD.SetArguments<Forwarder *>(this);
//     }
// }

void
Forwarder::onIncomingInterest(const Interest& interest, const FaceEndpoint& ingress)
{
  // receive Interest
  NFD_LOG_DEBUG("onIncomingInterest in=" << ingress << " interest=" << interest.getName());
            
    nfd::face::Transport* mytransport = ingress.face.getTransport();
    ns3::Ptr<ns3::Node> mynode =nullptr;
    if(ingress.face.getRemoteUri().getScheme() == "netdev")
    {
        ns3::Ptr<ns3::NetDevice> mydevice = dynamic_cast<ns3::ndn::NetDeviceTransport*>(mytransport)->GetNetDevice();
        ns3::Ptr<ns3::Channel> mychannel = mydevice->GetChannel();
        ns3::Ptr<ns3::PointToPointChannel> p2pChannel = mychannel->GetObject<ns3::PointToPointChannel>();
        ns3::Ptr<ns3::PointToPointNetDevice> p2pNetDevice = ns3::DynamicCast<ns3::PointToPointNetDevice>(p2pChannel->GetDevice(1));
        mynode = p2pNetDevice->GetNode();
        mynodeid = mynode->GetId();
        NFD_LOG_DEBUG("nodeid"<<mynodeid);
    }

    auto prefix=interest.getName().getPrefix(1).toUri();
    NFD_LOG_DEBUG("prefix: "<<prefix);
    // if(mynodeid==BTNkId){
    //     //丢弃恶意端口的兴趣包
    //     if(maliciousFace.find(ingress.face.getId())!=maliciousFace.end()){
    //       NFD_LOG_DEBUG("discard interest from malicious face: "<<ingress.face.getId());
    //       if(numDropInterestOfFace.find(ingress.face.getId())!=numDropInterestOfFace.end()){
    //         //如果丢弃兴趣包，则在一个RTT后视为未满足的兴趣包
    //         //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterestOfFace[ingress.face.getId()]+=1; });
    //         numDropInterestOfFace[ingress.face.getId()]+=1;
    //       }
    //       else{
    //         //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterestOfFace[ingress.face.getId()]=1; });
    //         numDropInterestOfFace[ingress.face.getId()]=1;
    //       }
    //       if(numDropInterest.find(prefix)!=numDropInterest.end()){
    //         //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterest[prefix]+=1; });
    //         numDropInterest[prefix]+=1;
    //       }
    //       else{
    //         //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterest[prefix]=1; });
    //         numDropInterest[prefix]=1;
    //       }
    //       return;
    //     }
    //     //丢弃恶意前缀
    //     if((maliciousPrefix.find(prefix)!=maliciousPrefix.end())&&(mynodeid==BTNkId)){
    //       NFD_LOG_DEBUG("discard malicious prefix");
    //       if(numDropInterestOfFace.find(ingress.face.getId())!=numDropInterestOfFace.end()){
    //         //如果丢弃兴趣包，则在一个RTT后视为未满足的兴趣包
    //         //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterestOfFace[ingress.face.getId()]+=1; });
    //         numDropInterestOfFace[ingress.face.getId()]+=1;
    //       }
    //       else{
    //         //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterestOfFace[ingress.face.getId()]=1; });
    //         numDropInterestOfFace[ingress.face.getId()]=1;
    //       }
    //       if(numDropInterest.find(prefix)!=numDropInterest.end()){
    //         //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterest[prefix]+=1; });
    //         numDropInterest[prefix]+=1;
    //       }
    //       else{
    //         //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterest[prefix]=1; });
    //         numDropInterest[prefix]=1;
    //       }
    //       NFD_LOG_DEBUG("numDropInterest: "<<numDropInterest[prefix]);
    //       return;
    //     }
    // }
    if(prefix != "/localhost"){
      if(allPrefix.insert(prefix).second){//新前缀
        allocPit[prefix]=minAllocPit;//初始化前缀桶
        //tao[prefix]=1;//初始化波动状态
        numInterest[prefix]=0;//初始化numInterest
        rate[prefix]=0;
        curPit[prefix]=0;//初始化curPit
        unallocPitCapacity=pitTotalCapacity-allPrefix.size()*minAllocPit;//更新未分配空间
      }
      numInterest[prefix]+=1;
      if(edgeId.find(mynodeid)!=edgeId.end()){//边缘节点
          if(numInterestOfFace.find(ingress.face.getId())!=numInterestOfFace.end()){
            numInterestOfFace[ingress.face.getId()]++;
          }
          else{
            numInterestOfFace[ingress.face.getId()]=1;
          }
          if(numInterestOfFacePrefix.find(std::make_pair(ingress.face.getId(), prefix))!=numInterestOfFacePrefix.end()){
            numInterestOfFacePrefix[std::make_pair(ingress.face.getId(), prefix)] += 1;
          }
          else{
            numInterestOfFacePrefix[std::make_pair(ingress.face.getId(), prefix)] = 1;
          }
      }
      NFD_LOG_DEBUG("curPit"<<curPit[prefix]);
      NFD_LOG_DEBUG("allocPit"<<allocPit[prefix]);
      NFD_LOG_DEBUG("curUnallocPit"<<curUnallocPit);
      NFD_LOG_DEBUG("unallocPitCapacity"<<unallocPitCapacity);
      if((totalPit>pitTotalCapacity)&&(mynodeid==BTNkId)){//只有瓶颈节点（非用户）分配PIT和丢弃兴趣包
        NFD_LOG_DEBUG("total pit capacity full, discard");
        if(numDropInterestOfFace.find(ingress.face.getId())!=numDropInterestOfFace.end()){
          //如果丢弃兴趣包，则在一个RTT后视为未满足的兴趣包
          //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterestOfFace[ingress.face.getId()]+=1; });
          numDropInterestOfFace[ingress.face.getId()]+=1;
        }
        else{
          //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterestOfFace[ingress.face.getId()]=1; });
          numDropInterestOfFace[ingress.face.getId()]=1;
        }
        if(numDropInterest.find(prefix)!=numDropInterest.end()){
          //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterest[prefix]+=1; });
          numDropInterest[prefix]+=1;
        }
        else{
          //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterest[prefix]=1; });
          numDropInterest[prefix]=1;
        }
        return;
      }
      // if(allocPit.find(prefix)==allocPit.end()){
      //   allocPit[prefix]=minAllocPit;
      // }
      if((curPit[prefix]>allocPit[prefix])&&(mynodeid==BTNkId)){
        if(curUnallocPit<unallocPitCapacity){//插入未分配空间
          NFD_LOG_DEBUG("curUnallocPit"<<curUnallocPit);
          NFD_LOG_DEBUG("unallocPitCapacity"<<unallocPitCapacity);
          NFD_LOG_DEBUG("prefix pit capicity full, insert to unalloct");
          unallocName.insert(interest.getName().toUri());
          curUnallocPit++;
          sendInterestTime[interest.getName().toUri()]=ns3::Simulator::Now();
          totalPit++;
        }
        else{
          NFD_LOG_DEBUG("prefix pit and unalloc all full, discard");
          if(numDropInterestOfFace.find(ingress.face.getId())!=numDropInterestOfFace.end()){
            //如果丢弃兴趣包，则在一个RTT后视为未满足的兴趣包
            //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterestOfFace[ingress.face.getId()]+=1; });
            numDropInterestOfFace[ingress.face.getId()]+=1;
          }
          else{
            //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterestOfFace[ingress.face.getId()]=1; });
            numDropInterestOfFace[ingress.face.getId()]=1;
          }
          if(numDropInterest.find(prefix)!=numDropInterest.end()){
            //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterest[prefix]+=1; });
            numDropInterest[prefix]+=1;
          }
          else{
            //getScheduler().schedule(time::milliseconds(200), [=] { numDropInterest[prefix]=1; });
            numDropInterest[prefix]=1;
          }
          return;
        }
      }
      else{
      //插入前缀桶
        curPit[prefix]+=1;
        //记录兴趣包发送时间(会被聚合请求覆盖)
        sendInterestTime[interest.getName().toUri()]=ns3::Simulator::Now();
        totalPit++;
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
  //NFD_LOG_DEBUG("pitEntry issatisied"<<pitEntry->isSatisfied);

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
  NFD_LOG_DEBUG("lastExpiryFromNow=" << lastExpiryFromNow);

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
  //消费者节点会触发
  if (!pitEntry->isSatisfied) {
    beforeExpirePendingInterest(*pitEntry);
    //兴趣包的lifetime（PITtimeout)为2s时，首先触发的是用户RTO，发出新的相同兴趣，刷新PIT，所以基本上不会存在未被满足的PIT达到timeout，所以代码基本上没有运行到此处
    auto prefix = pitEntry->getName().getPrefix(1).toUri();
    NFD_LOG_DEBUG("prefix"<<prefix);
    curPit[prefix]--;
    delaySeries[prefix].push_back(PitTimeout);
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

    //放在outgoingdata里面，因为contentHit的data不会经过incomingData
  auto prefix=data.getName().getPrefix(1).toUri();
  NFD_LOG_DEBUG("prefix: "<<prefix);
  if(prefix != "/localhost"){
    totalPit--;
      if(numData.find(prefix)!=numData.end()){
        numData[prefix]++;
      }
      else{
        numData[prefix]=1;
      }
      if(unallocName.find(data.getName().toUri())!=unallocName.end()){//如果name在unalloc中
        unallocName.erase(data.getName().toUri());
        curUnallocPit--;
        NFD_LOG_DEBUG("curUnallocPit"<<curUnallocPit);
      }
      else{//如果name在前缀桶中
        //curPit减1
        curPit[prefix]-=1;
        NFD_LOG_DEBUG("curPit"<<curPit[prefix]);
      }
      //delay
      //NFD_LOG_DEBUG("now: "<<ns3::Simulator::Now() <<"sendTime "<< sendInterestTime[data.getName().toUri()]);
      auto del=ns3::Simulator::Now() - sendInterestTime[data.getName().toUri()];
      NFD_LOG_DEBUG("delay:"<<del);
      NFD_LOG_DEBUG("egress.getId()"<<egress.getId());
      if(delaySeriesOfFace.find(egress.getId())!=delaySeriesOfFace.end()){
          delaySeriesOfFace[egress.getId()].push_back(del);
      }
      else{
          delaySeriesOfFace[egress.getId()] = std::vector<ns3::Time>();
          delaySeriesOfFace[egress.getId()].push_back(del);
      }
      // for (auto it = delaySeriesOfFace[egress.getId()].begin(); it != delaySeriesOfFace[egress.getId()].end(); ++it) {
      //   std::cout << "Key: " << *it << std::endl;
      // }
      if(delaySeries.find(prefix)!=delaySeries.end()){
          delaySeries[prefix].push_back(del);
      }
      else{
          delaySeries[prefix] = std::vector<ns3::Time>();
          delaySeries[prefix].push_back(del);
      }
      
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

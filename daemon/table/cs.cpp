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

#include "cs.hpp"
#include "common/logger.hpp"
#include "core/algorithm.hpp"

#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/util/concepts.hpp>

namespace nfd {
namespace cs {

NFD_LOG_INIT(ContentStore);

static unique_ptr<Policy>
makeDefaultPolicy()
{
  return Policy::create("lru");
}

Cs::Cs(size_t nMaxPackets)
{
  setPolicyImpl(makeDefaultPolicy());
  m_policy->setLimit(nMaxPackets/2);//每个cs区域分配一半大小
}

void
Cs::insert(const Data& data, bool isUnsolicited)
{
  if (!m_shouldAdmit || m_policy->getLimit() == 0) {
    return;
  }
  NFD_LOG_DEBUG("insert " << data.getName());

  // recognize CachePolicy
  shared_ptr<lp::CachePolicyTag> tag = data.getTag<lp::CachePolicyTag>();
  if (tag != nullptr) {
    lp::CachePolicyType policy = tag->get().getPolicy();
    if (policy == lp::CachePolicyType::NO_CACHE) {
      return;
    }
  }

  const_iterator it;
  bool isNewEntry = false;
  std::tie(it, isNewEntry) = m_table_unp.emplace(data.shared_from_this(), isUnsolicited);//插入非保护区,使用emplce可以自动将传入参数转化为Entry变量并插入
  Entry& entry = const_cast<Entry&>(*it);

  entry.updateFreshUntil();

  if (!isNewEntry) { // existing entry
    // XXX This doesn't forbid unsolicited Data from refreshing a solicited entry.
    if (entry.isUnsolicited() && !isUnsolicited) {
      entry.clearUnsolicited();
    }
    NFD_LOG_DEBUG("不是newEntry");
    m_policy->afterRefresh(*it, unprotectedRegion);
  }
  else {
    NFD_LOG_DEBUG("是newEntry");
    m_policy->afterInsert(*it, unprotectedRegion);
  }
}

std::pair<Cs::const_iterator, Cs::const_iterator>
Cs::findPrefixRange(const Name& prefix, csRegion i)const
{
  switch (i)
  {
  case protectedRegion://查找保护区
    {auto first = m_table_prt.lower_bound(prefix);//返回大于等于prefix的迭代器
    auto last = m_table_prt.end();
    if (prefix.size() > 0) {
      last = m_table_prt.lower_bound(prefix.getSuccessor());//getSuccessor是让name的最后一个组件变成排序意义下的后一个值
    }
    return {first, last};}//在case中声明变量会有范围问题，所以加上大括号
    break;
  default://查找非保护区
    {auto first = m_table_unp.lower_bound(prefix);//返回大于等于prefix的迭代器
    auto last = m_table_unp.end();
    if (prefix.size() > 0) {
      last = m_table_unp.lower_bound(prefix.getSuccessor());//getSuccessor是让name的最后一个组件变成排序意义下的后一个值
    }
    return {first, last};}
    break;
  }
}

size_t
Cs::eraseImpl(const Name& prefix, size_t limit)
{
  const_iterator i, last;
  size_t nErased = 0;
  //分别删除cs两个区域
  std::tie(i, last) = findPrefixRange(prefix,protectedRegion);
  while (i != last && nErased < limit) {
    m_policy->beforeErase(*i, protectedRegion);
    i = m_table_prt.erase(i);
    ++nErased;
  }

  std::tie(i, last) = findPrefixRange(prefix,unprotectedRegion);
  while (i != last && nErased < limit) {
    m_policy->beforeErase(*i, unprotectedRegion);
    i = m_table_unp.erase(i);
    ++nErased;
  }

  return nErased;

  // std::tie(i, last) = findPrefixRange(prefix);

  // size_t nErased = 0;
  // while (i != last && nErased < limit) {
  //   m_policy->beforeErase(i);
  //   i = m_table.erase(i);
  //   ++nErased;
  // }
  // return nErased;
}

std::pair<Data, bool>
Cs::findImpl(const Interest& interest, int* isUnpHit)
{
  auto emptyData=Data(interest.getName());
  // NFD_LOG_DEBUG("table_prt中有");
  // for(auto ii=m_table_prt.begin();ii!=m_table_prt.end();++ii){
  //   NFD_LOG_DEBUG((ii)->getName());
  // }
  // NFD_LOG_DEBUG("table_unp中有");
  // for(auto ii=m_table_unp.begin();ii!=m_table_unp.end();++ii){
  //   NFD_LOG_DEBUG((ii)->getName());
  // }
  // m_policy->printQueue();
  if (!m_shouldServe || m_policy->getLimit() == 0) {
    // return m_table_prt.end();
    return std::make_pair(emptyData, false);
  }

  const Name& prefix = interest.getName();
  //先检查保护区cs
  auto range = findPrefixRange(prefix, protectedRegion);
  auto match = std::find_if(range.first, range.second,
                            [&interest] (const auto& entry) { return entry.canSatisfy(interest); });
  //保护区cs未命中，再检查非保护区
  if (match == range.second) {
    range = findPrefixRange(prefix, unprotectedRegion);
    match = std::find_if(range.first, range.second,
                            [&interest] (const auto& entry) { return entry.canSatisfy(interest); });
    //非保护区也没有命中
    if (match == range.second) {
    NFD_LOG_DEBUG("find " << prefix << " no-match");
      // return m_table_prt.end();
      return std::make_pair(emptyData, false);
    }
    else{//非保护区命中
    NFD_LOG_DEBUG("非保护区find " << prefix << " matching " << match->getName());
    auto data=match->getData();
    NFD_LOG_DEBUG("命中data= "<<data.getName());
    if(data.getSignatureInfo().getSignatureType()==255){
      NFD_LOG_DEBUG("命中data为真");
      m_policy->beforeUse(*match, unprotectedRegion);
    }
    else{
      NFD_LOG_DEBUG("命中data为假,删除table和queue");
      eraseImpl(interest.getName(),5);
    }
    *isUnpHit=1;
    NFD_LOG_DEBUG("isUnpHit= "<<*isUnpHit);
    // return *match;
    return std::make_pair(data, true);
  }
  }
  else{//保护区命中
    NFD_LOG_DEBUG("保护区find " << prefix << " matching " << match->getName());
    auto data=match->getData();
    NFD_LOG_DEBUG("命中data= "<<data.getName());
    m_policy->beforeUse(*match, protectedRegion);
    // return *match;
    return std::make_pair(data, true);
  }
  // auto range = findPrefixRange(prefix);
  // auto match = std::find_if(range.first, range.second,
  //                           [&interest] (const auto& entry) { return entry.canSatisfy(interest); });

  // if (match == range.second) {
  //   NFD_LOG_DEBUG("find " << prefix << " no-match");
  //   return m_table.end();
  // }
  // NFD_LOG_DEBUG("find " << prefix << " matching " << match->getName());
  // m_policy->beforeUse(match);
  // return match;
}

void
Cs::dump()
{
  NFD_LOG_DEBUG("dump table");
  // for (const Entry& entry : m_table) {
  //   NFD_LOG_TRACE(entry.getFullName());
  // }
  for (const Entry& entry : m_table_prt) {
    NFD_LOG_TRACE(entry.getFullName());
  }
  for (const Entry& entry : m_table_unp) {
    NFD_LOG_TRACE(entry.getFullName());
  }
}

void
Cs::setPolicy(unique_ptr<Policy> policy)
{
  BOOST_ASSERT(policy != nullptr);
  BOOST_ASSERT(m_policy != nullptr);
  size_t limit = m_policy->getLimit();
  this->setPolicyImpl(std::move(policy));
  m_policy->setLimit(limit);
}

void
Cs::setPolicyImpl(unique_ptr<Policy> policy)
{
  NFD_LOG_DEBUG("set-policy " << policy->getName());
  m_policy = std::move(policy);
  // m_beforeEvictConnection = m_policy->beforeEvict.connect([this] (auto it) { m_table.erase(it); });
  m_beforeEvict_prtConnection = m_policy->beforeEvict_prt.connect([this] (auto it) { m_table_prt.erase(it);});
  m_beforeEvict_unpConnection = m_policy->beforeEvict_unp.connect([this] (auto it) { m_table_unp.erase(it);});
  m_beforeInsert_prtConnection = m_policy->beforeInsert_prt.connect([this] (auto it) { m_table_prt.insert(it);});
  m_beforeInsert_unpConnection = m_policy->beforeInsert_unp.connect([this] (auto it) { m_table_unp.insert(it);});

  m_policy->setCs(this);
  BOOST_ASSERT(m_policy->getCs() == this);
}

void
Cs::enableAdmit(bool shouldAdmit)
{
  if (m_shouldAdmit == shouldAdmit) {
    return;
  }
  m_shouldAdmit = shouldAdmit;
  NFD_LOG_INFO((shouldAdmit ? "Enabling" : "Disabling") << " Data admittance");
}

void
Cs::enableServe(bool shouldServe)
{
  if (m_shouldServe == shouldServe) {
    return;
  }
  m_shouldServe = shouldServe;
  NFD_LOG_INFO((shouldServe ? "Enabling" : "Disabling") << " Data serving");
}

void
Cs::csVerify(shared_ptr<ndn::Data> data1)
{ 
    auto hc=0;
    auto hopCountTag = data1->getTag<lp::HopCountTag>();
    if (hopCountTag != nullptr) { // e.g., packet came from local node's cache
      data1->setTag(make_shared<lp::HopCountTag>(hc));
    }
    // uint32_t ei=0;
    // uint64_t seq=data1->getName().get(-1).toSequenceNumber();
    // auto str=data1->getName().toUri(ndn::name::UriFormat::CANONICAL);
    // char* p;
    // uint64_t name=std::strtoul(str.c_str(), &p, 10);//使用stoul报错
    // NFD_LOG_DEBUG("name变成str: "<<str.c_str());

  //   //只插入seq，不适用于为网络存在多个prefix的情况
  // if(hasVerifiedFilter.Contain(seq, ei)==0){
  //     NFD_LOG_DEBUG("命中缓存在过滤器中找到，无需验证"<<seq);
  // }
  // else{
  //   NFD_LOG_DEBUG("命中缓存没有在过滤器中找到，需要验证"<<seq);
  //   data1->setTag(make_shared<ndn::lp::ExtraDelayTag>(4));//一次验证4ms（验证公钥和验证签名）
  // }
  //如果命中缓存是假包，把SignatureTypeValue改为100，表示NACK
  if(data1->getSignatureInfo().getSignatureType()==2){
    NFD_LOG_DEBUG("命中缓存是假包, 将其SignatureType改为100 "<<data1->getName());
    shared_ptr<ndn::SignatureInfo> signatureInfo1 = make_shared<ndn::SignatureInfo>(const_cast<ndn::SignatureInfo&>(data1->getSignatureInfo()));
    signatureInfo1->setSignatureType(static_cast< ::ndn::tlv::SignatureTypeValue>(100));//100表示我验证过的假包
    data1->setSignatureInfo(*signatureInfo1);
    //this->erase(data1->getName(),5,[=] (size_t nErased){}) ;//删除污染缓存
  }
  else{
    NFD_LOG_DEBUG("命中缓存是真包 "<<data1->getName());
  }
}

void 
Cs::outlog(std::string str){
  NFD_LOG_DEBUG(str);
}

} // namespace cs
} // namespace nfd

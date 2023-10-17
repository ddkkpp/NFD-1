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

#include "cs-policy-lru.hpp"
#include "cs.hpp"
#include "common/logger.hpp"
#include <initializer_list>

NFD_LOG_INIT(cs-policy-lru);

namespace nfd {
namespace cs {
namespace lru {

const std::string LruPolicy::POLICY_NAME = "lru";
NFD_REGISTER_CS_POLICY(LruPolicy);

LruPolicy::LruPolicy()
  : Policy(POLICY_NAME)
{
}

void
LruPolicy::doAfterInsert(EntryRef i, enum csRegion j)
{
  NFD_LOG_DEBUG("enter doAfterInsert");
  this->insertToQueue(i, true, j);
  this->evictEntries(j);
}

void
LruPolicy::doAfterRefresh(EntryRef i, enum csRegion j)
{
  NFD_LOG_DEBUG("enter doAfterRefresh");
  this->insertToQueue(i, false, j);
}

void
LruPolicy::doBeforeErase(EntryRef i, enum csRegion j)
{
  switch (j)
  {
  case protectedRegion:
    m_queue_prt.get<1>().erase(i);
    break;
  case unprotectedRegion:
    m_queue_unp.get<1>().erase(i);
    break;
  default:
    break;
  }
  //m_queue.get<1>().erase(i);
}

void
LruPolicy::doBeforeUse(EntryRef i, enum csRegion j)
{
  NFD_LOG_DEBUG("enter doBeforeUse");
  this->insertToQueue(i, false, j);
}

void
LruPolicy::evictEntries(enum csRegion j)
{
  NFD_LOG_DEBUG("enter evictEntries");
  BOOST_ASSERT(this->getCs() != nullptr);
  switch (j)
  {
  case protectedRegion:
    //保护区内容删除后移入非保护区
    NFD_LOG_DEBUG("准备删除保护区内容");
    // NFD_LOG_DEBUG("size_prt= "<<this->getCs()->size_prt()<<" limit= "<<this->getLimit());
    // while (this->getCs()->size_prt() > this->getLimit()) {
    NFD_LOG_DEBUG("size_prt= "<<m_queue_prt.size()<<" limit= "<<this->getLimit());
    while (m_queue_prt.size() > this->getLimit()/5) {
      NFD_LOG_DEBUG("实际删除保护区内容");
      BOOST_ASSERT(!m_queue_prt.empty());
      EntryRef i = m_queue_prt.front();
      NFD_LOG_DEBUG("删除queue_prt");
      m_queue_prt.pop_front();
      NFD_LOG_DEBUG("触发cs的table_prt的删除");
      this->emitSignal(beforeEvict_prt, i);
      NFD_LOG_DEBUG("准备插入非保护区");
      this->insertToQueue(i,true,unprotectedRegion);
      NFD_LOG_DEBUG("触发cs的table_unp的插入");
      this->emit_beforeInsert_unp(i);
      NFD_LOG_DEBUG("准备删除非保护区");
      this->evictEntries(unprotectedRegion);
      // NFD_LOG_DEBUG("queue_prt中有");
      // for(auto ii=m_queue_prt.begin();ii!=m_queue_prt.end();++ii){
      //   NFD_LOG_DEBUG((ii)->getName());
      // }
    }
    break;
  case unprotectedRegion: 
    NFD_LOG_DEBUG("准备删除非保护区内容");
    // NFD_LOG_DEBUG("size_unp= "<<this->getCs()->size_unp()<<" limit= "<<this->getLimit());
    // while (this->getCs()->size_unp() > this->getLimit()) {
    NFD_LOG_DEBUG("size_unp= "<<m_queue_unp.size()<<" limit= "<<this->getLimit());
    while (m_queue_unp.size() > this->getLimit()*9/5) {
      NFD_LOG_DEBUG("实际删除非保护区内容");
      BOOST_ASSERT(!m_queue_unp.empty());
      NFD_LOG_DEBUG("删除queue_unp");
      EntryRef i = m_queue_unp.front();
      m_queue_unp.pop_front();
      NFD_LOG_DEBUG("触发cs的table_unp的删除");
      this->emitSignal(beforeEvict_unp, i);
      NFD_LOG_DEBUG("删除完毕");
      // NFD_LOG_DEBUG("queue_unp中有");
      // for(auto ii=m_queue_unp.begin();ii!=m_queue_unp.end();++ii){
      //   NFD_LOG_DEBUG((ii)->getName());
      // }
    }
  
  default:
    break;
  }
  // while (this->getCs()->size() > this->getLimit()) {
  //   BOOST_ASSERT(!m_queue.empty());
  //   EntryRef i = m_queue.front();
  //   m_queue.pop_front();
  //   this->emitSignal(beforeEvict, i);
  // }
}

void
LruPolicy::insertToQueue(EntryRef i, bool isNewEntry, enum csRegion j)
{
  NFD_LOG_DEBUG("enter insertToQueue");
  Queue::iterator it;
  bool isNew = false;

  switch (j)
  {
  case protectedRegion:
    NFD_LOG_DEBUG("插入protectedRegion前");
    // NFD_LOG_DEBUG("queue_prt中有");
    if(m_queue_prt.empty()){
      NFD_LOG_DEBUG("queue_prt为空");
    }
    // for(auto ii=m_queue_prt.begin();ii!=m_queue_prt.end();++ii){
    //   NFD_LOG_DEBUG((ii)->getName());
    // }
    std::tie(it, isNew) = m_queue_prt.push_back(i);
    NFD_LOG_DEBUG("isNewEntry= "<<isNewEntry);
    NFD_LOG_DEBUG("isNew= "<<isNew);
    BOOST_ASSERT(isNew == isNewEntry);
    if (!isNewEntry) {
      m_queue_prt.relocate(m_queue_prt.end(), it);
    }
    // NFD_LOG_DEBUG("queue_prt中有");
    // for(auto ii=m_queue_prt.begin();ii!=m_queue_prt.end();++ii){
    //   NFD_LOG_DEBUG((ii)->getName());
    // }
    // NFD_LOG_DEBUG("size_prt= "<<this->getCs()->size_prt());
    NFD_LOG_DEBUG("size_prt= "<<m_queue_prt.size());
    break;
  case unprotectedRegion:
    NFD_LOG_DEBUG("插入unprotectedRegion前");
    // NFD_LOG_DEBUG("queue_unp中有");
    // for(auto ii=m_queue_unp.begin();ii!=m_queue_unp.end();++ii){
    //   NFD_LOG_DEBUG((ii)->getName());
    // }
    std::tie(it, isNew) = m_queue_unp.push_back(i);
    NFD_LOG_DEBUG("isNewEntry= "<<isNewEntry);
    NFD_LOG_DEBUG("isNew= "<<isNew);
    BOOST_ASSERT(isNew == isNewEntry);
    if (!isNewEntry) {
    //非保护区内容命中后移入保护区
        //  m_queue_unp.relocate(m_queue_unp.end(), it);
      NFD_LOG_DEBUG("删除queue_unp");
      m_queue_unp.erase(it);
      NFD_LOG_DEBUG("触发cs的table_unp的剔除");
      this->emitSignal(beforeEvict_unp, i);//使得cs中的m_table_unp也同步删除
      NFD_LOG_DEBUG("准备插入保护区");
      this->insertToQueue(i,true,protectedRegion);
      NFD_LOG_DEBUG("触发cs的table_prt的插入");
      this->emitSignal(beforeInsert_prt, i);
      NFD_LOG_DEBUG("准备删除保护区");
      this->evictEntries(protectedRegion);
    }
    // NFD_LOG_DEBUG("queue_unp中有");
    // for(auto ii=m_queue_unp.begin();ii!=m_queue_unp.end();++ii){
    //   NFD_LOG_DEBUG((ii)->getName());
    // }
    //NFD_LOG_DEBUG("size_unp= "<<this->getCs()->size_unp());
    NFD_LOG_DEBUG("size_unp= "<<m_queue_unp.size());
    break;
  default:
    break;
  }
  // // push_back only if i does not exist
  // std::tie(it, isNew) = m_queue.push_back(i);

  // BOOST_ASSERT(isNew == isNewEntry);
  // if (!isNewEntry) {
  //   m_queue.relocate(m_queue.end(), it);
  // }
  
}

void
LruPolicy::printQueue()
{
    NFD_LOG_DEBUG("queue_prt中有");
    for(auto ii=m_queue_prt.begin();ii!=m_queue_prt.end();++ii){
      NFD_LOG_DEBUG((ii)->getName());
    }
     NFD_LOG_DEBUG("queue_unp中有");
    for(auto ii=m_queue_unp.begin();ii!=m_queue_unp.end();++ii){
      NFD_LOG_DEBUG((ii)->getName());
    }
}

} // namespace lru
} // namespace cs
} // namespace nfd

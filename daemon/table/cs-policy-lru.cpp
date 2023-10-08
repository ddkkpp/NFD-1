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
  this->insertToQueue(i, true, j);
  this->evictEntries(j);
}

void
LruPolicy::doAfterRefresh(EntryRef i, enum csRegion j)
{
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
  this->insertToQueue(i, false, j);
}

void
LruPolicy::evictEntries(enum csRegion j)
{
  BOOST_ASSERT(this->getCs() != nullptr);
  switch (j)
  {
  case protectedRegion:
    //保护区内容删除后移入非保护区
    while (this->getCs()->size_prt() > this->getLimit()) {
      BOOST_ASSERT(!m_queue_prt.empty());
      EntryRef i = m_queue_prt.front();
      m_queue_prt.pop_front();
      this->emitSignal(beforeEvict_prt, i);
      this->doAfterInsert(i, unprotectedRegion);
    }
    break;
  case unprotectedRegion:
    while (this->getCs()->size_unp() > this->getLimit()) {
      BOOST_ASSERT(!m_queue_unp.empty());
      EntryRef i = m_queue_unp.front();
      m_queue_unp.pop_front();
      this->emitSignal(beforeEvict_unp, i);
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
  Queue::iterator it;
  bool isNew = false;

  switch (j)
  {
  case protectedRegion:
    std::tie(it, isNew) = m_queue_prt.push_back(i);
    BOOST_ASSERT(isNew == isNewEntry);
    if (!isNewEntry) {
      m_queue_prt.relocate(m_queue_prt.end(), it);
    }
    break;
  case unprotectedRegion:
    std::tie(it, isNew) = m_queue_unp.push_back(i);
    BOOST_ASSERT(isNew == isNewEntry);
    if (!isNewEntry) {
    //非保护区内容命中后移入保护区
      this->insertToQueue(i, true, protectedRegion);
      m_queue_unp.pop_front();
    }
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

} // namespace lru
} // namespace cs
} // namespace nfd

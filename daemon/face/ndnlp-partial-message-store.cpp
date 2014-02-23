/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2014 Named Data Networking Project
 * See COPYING for copyright and distribution information.
 */

#include "ndnlp-partial-message-store.hpp"

namespace nfd {
namespace ndnlp {

PartialMessage::PartialMessage()
  : m_fragCount(0)
  , m_received(0)
  , m_totalLength(0)
{
}

bool
PartialMessage::add(uint16_t fragIndex, uint16_t fragCount, const Block& payload)
{
  if (m_received == 0) { // first packet
    m_fragCount = fragCount;
    m_payloads.resize(fragCount);
  }

  if (m_fragCount != fragCount || fragIndex >= m_fragCount) {
    return false;
  }

  if (!m_payloads[fragIndex].empty()) { // duplicate
    return false;
  }

  m_payloads[fragIndex] = payload;
  ++m_received;
  m_totalLength += payload.value_size();
  return true;
}

bool
PartialMessage::isComplete() const
{
  return m_received == m_fragCount;
}

Block
PartialMessage::reassemble()
{
  BOOST_ASSERT(this->isComplete());

  ndn::BufferPtr buffer = make_shared<ndn::Buffer>(m_totalLength);
  uint8_t* buf = buffer->get();
  for (std::vector<Block>::const_iterator it = m_payloads.begin();
       it != m_payloads.end(); ++it) {
    const Block& payload = *it;
    memcpy(buf, payload.value(), payload.value_size());
    buf += payload.value_size();
  }

  return Block(buffer);
}

PartialMessageStore::PartialMessageStore(Scheduler& scheduler, time::Duration idleDuration)
  : m_scheduler(scheduler)
  , m_idleDuration(idleDuration)
{
}

PartialMessageStore::~PartialMessageStore()
{
}

void
PartialMessageStore::receiveNdnlpData(const Block& pkt)
{
  NdnlpData parsed;
  parsed.wireDecode(pkt);
  if (parsed.m_fragCount == 1) { // single fragment
    this->onReceive(parsed.m_payload.blockFromValue());
    return;
  }

  uint64_t messageIdentifier = parsed.m_seq - parsed.m_fragIndex;
  shared_ptr<PartialMessage> pm = m_partialMessages[messageIdentifier];
  if (!static_cast<bool>(pm)) {
    m_partialMessages[messageIdentifier] = pm = make_shared<PartialMessage>();
  }
  this->scheduleCleanup(messageIdentifier, pm);

  pm->add(parsed.m_fragIndex, parsed.m_fragCount, parsed.m_payload);
  if (pm->isComplete()) {
    this->onReceive(pm->reassemble());
    this->cleanup(messageIdentifier);
  }
}

void
PartialMessageStore::scheduleCleanup(uint64_t messageIdentifier,
                                     shared_ptr<PartialMessage> partialMessage)
{
  partialMessage->m_expiry = m_scheduler.scheduleEvent(m_idleDuration,
    bind(&PartialMessageStore::cleanup, this, messageIdentifier));
}

void
PartialMessageStore::cleanup(uint64_t messageIdentifier)
{
  std::map<uint64_t, shared_ptr<PartialMessage> >::iterator it =
    m_partialMessages.find(messageIdentifier);
  if (it == m_partialMessages.end()) {
    return;
  }

  m_scheduler.cancelEvent(it->second->m_expiry);
  m_partialMessages.erase(it);
}

} // namespace ndnlp
} // namespace nfd

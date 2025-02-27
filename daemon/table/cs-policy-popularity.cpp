#include "cs-policy-popularity.hpp"
#include "cs.hpp"
#include "common/logger.hpp"

namespace nfd {
namespace cs {
namespace popularity {

const std::string PopularityPolicy::POLICY_NAME = "popularity";
NFD_REGISTER_CS_POLICY(PopularityPolicy);

NFD_LOG_INIT(PopularityPolicy);//有这个才能用NFD_LOG_DEBUG

PopularityPolicy::PopularityPolicy()
  : Policy(POLICY_NAME)
{
}

void
PopularityPolicy::doAfterInsert(EntryRef i, double popularity)
{
  this->insertToQueue(i, popularity);
  this->evictEntries();
}

void
PopularityPolicy::doAfterRefresh(EntryRef i, double popularity)
{
  this->insertToQueue(i, popularity);
}

void
PopularityPolicy::doBeforeErase(EntryRef i)
{
  auto it = m_entryMap.find(i);
  if (it != m_entryMap.end()) {
    m_queue.erase(it->second);
    m_entryMap.erase(it);
  }
}

void
PopularityPolicy::doBeforeUse(EntryRef i, double popularity)
{
  this->insertToQueue(i, popularity);
}

void
PopularityPolicy::evictEntries()
{
  BOOST_ASSERT(this->getCs() != nullptr);
  while (this->getCs()->size() > this->getLimit()) {
    BOOST_ASSERT(!m_queue.empty());
    auto it = m_queue.begin();
    EntryRef i = it->second;
    auto seq = i->getName().get(1).toSequenceNumber();
    double popularity = it->first;
    NFD_LOG_DEBUG("evict seq=" << seq << " popularity=" << popularity);
    m_queue.erase(it);
    this->emitSignal(beforeEvict, i);
  }
}

void
PopularityPolicy::insertToQueue(EntryRef i, double popularity)
{
  auto range = m_queue.equal_range(popularity);
  for (auto it = range.first; it != range.second; ++it) {
    if (it->second == i) {
      auto seq = i->getName().get(1).toSequenceNumber();
      NFD_LOG_DEBUG("insert seq=" << seq << " popularity=" << popularity);  
      m_queue.erase(it);
      m_entryMap.erase(i);
      break;
    }
  }
  auto it = m_queue.insert(std::make_pair(popularity, i));
  m_entryMap[i] = it;
}

} // namespace popularity
} // namespace cs
} // namespace nfd

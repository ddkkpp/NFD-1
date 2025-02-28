#include "cs-policy-popularity.hpp"
#include "cs.hpp"
#include "common/logger.hpp"

namespace nfd {
namespace cs {
namespace popularity {


// PopularityPolicy implementation
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
  // 使用第二个索引(按EntryRef)来删除
  auto& entryIndex = m_queue.get<1>();
  entryIndex.erase(i);
}

void
PopularityPolicy::doBeforeUse(EntryRef i, double popularity)
{
  this->insertToQueue(i, popularity);
}

void
PopularityPolicy::evictEntries()
{
  NFD_LOG_INFO("evictEntries");
  BOOST_ASSERT(this->getCs() != nullptr);
  
  // 使用第一个索引(按popularity排序)来淘汰
  auto& popularityIndex = m_queue.get<0>();
  
  while (this->getCs()->size() > this->getLimit()) {
    if (popularityIndex.empty()) {
      break;
    }
    
    auto it = popularityIndex.begin(); // 获取popularity最小的条目
    EntryRef entryToEvict = it->entry;
    double popularity = it->popularity;
    
    NFD_LOG_DEBUG("evict " << entryToEvict->getName() << " popularity=" << popularity);
    popularityIndex.erase(it);
    this->emitSignal(beforeEvict, entryToEvict);
  }
}

void
PopularityPolicy::insertToQueue(EntryRef i, double popularity)
{
  NFD_LOG_DEBUG("insert " << i->getName() << " popularity=" << popularity);
  
  // 如果entry已存在，会自动替换旧的
  m_queue.insert(Entry(popularity, i));
}

} // namespace popularity
} // namespace cs
} // namespace nfd

#ifndef NFD_DAEMON_TABLE_CS_POLICY_POPULARITY_HPP
#define NFD_DAEMON_TABLE_CS_POLICY_POPULARITY_HPP

#include "cs-policy.hpp"
#include <map>
#include <unordered_map>

namespace nfd {
namespace cs {
namespace popularity {

using PopularityQueue = std::multimap<double, Policy::EntryRef>;

/** \brief Popularity-based replacement policy
 */
class PopularityPolicy final : public Policy
{
public:
  PopularityPolicy();

public:
  static const std::string POLICY_NAME;

private:
  void
  doAfterInsert(EntryRef i, double popularity) final;

  void
  doAfterRefresh(EntryRef i, double popularity) final;

  void
  doBeforeErase(EntryRef i) final;

  void
  doBeforeUse(EntryRef i, double popularity) final;

  void
  evictEntries() final;

private:
  void
  insertToQueue(EntryRef i, double popularity);

private:
  PopularityQueue m_queue;
  std::unordered_map<EntryRef, PopularityQueue::iterator> m_entryMap;
};

} // namespace popularity

using popularity::PopularityPolicy;

} // namespace cs
} // namespace nfd

#endif // NFD_DAEMON_TABLE_CS_POLICY_POPULARITY_HPP

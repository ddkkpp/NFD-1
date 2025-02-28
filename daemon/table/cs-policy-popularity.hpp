#ifndef NFD_DAEMON_TABLE_CS_POLICY_POPULARITY_HPP
#define NFD_DAEMON_TABLE_CS_POLICY_POPULARITY_HPP

#include "cs-policy.hpp"
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>

namespace nfd {
namespace cs {
namespace popularity {

struct Entry 
{
  Entry(double p, Policy::EntryRef e) : popularity(p), entry(e) {}
  double popularity;
  Policy::EntryRef entry;
};

using Queue = boost::multi_index_container<
  Entry,
  boost::multi_index::indexed_by<
    // 按popularity排序的索引
    boost::multi_index::ordered_non_unique<
      boost::multi_index::member<Entry, double, &Entry::popularity>
    >,
    // 按EntryRef排序的唯一索引
    boost::multi_index::ordered_unique<
      boost::multi_index::member<Entry, Policy::EntryRef, &Entry::entry>
    >
  >
>;

class PopularityPolicy final : public Policy
{
public:
  PopularityPolicy();
  static const std::string POLICY_NAME;

private:
  void doAfterInsert(EntryRef i, double popularity) final;
  void doAfterRefresh(EntryRef i, double popularity) final;
  void doBeforeErase(EntryRef i) final;
  void doBeforeUse(EntryRef i, double popularity) final;
  void evictEntries() final;

private:
  void insertToQueue(EntryRef i, double popularity);
  Queue m_queue;
};

} // namespace popularity

using popularity::PopularityPolicy;

} // namespace cs
} // namespace nfd

#endif // NFD_DAEMON_TABLE_CS_POLICY_POPULARITY_HPP

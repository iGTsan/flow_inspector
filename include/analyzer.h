#pragma once

#include <thread>
#include <unordered_set>
#include <shared_mutex>

#include "logger.h"
#include "events_handler.h"
#include "internal_structs.h"


namespace flow_inspector {


class Analyzer {
 public:
  Analyzer(Logger& logger, EventsHandler& events_handler) noexcept;

  void detectThreats(const internal::Packet& packet) noexcept;

  bool parseRule(const ::std::string& rule) noexcept;

  size_t getSignaturesCount() const noexcept;

  void setStatSpeed(size_t interval) noexcept;

  bool updateRulesFromFile(const ::std::string& filename) noexcept;

  ~Analyzer() noexcept;

 private:
  bool parseRulesFile(
      const ::std::string& filename,
      ::std::unordered_set<internal::Rule>& rules_container,
      ::std::unordered_set<
          ::std::unique_ptr<internal::Signature>,
          internal::UniquePtrSignatureHash,
          internal::UniquePtrSignatureEqual>& signatures_container) noexcept;

  bool parseRuleToContainer(
      const ::std::string& rule,
      ::std::unordered_set<internal::Rule>& rules_container,
      ::std::unordered_set<
          ::std::unique_ptr<internal::Signature>,
          internal::UniquePtrSignatureHash,
          internal::UniquePtrSignatureEqual>& signatures_container) noexcept;

  bool tryParseNative(const ::std::string& rule) noexcept;

  void loadRule(internal::Rule rule) noexcept;

  void printStats() noexcept;

  mutable ::std::shared_mutex rules_mutex_; 
  ::std::unordered_set<internal::Rule> rules_;
  ::std::unordered_set<
      ::std::unique_ptr<internal::Signature>,
      internal::UniquePtrSignatureHash,
      internal::UniquePtrSignatureEqual> signatures_;
  
  Logger& logger_;
  EventsHandler& events_handler_;
  ::std::atomic<size_t> packets_count_;
  ::std::atomic<bool> done_{false};
  ::std::size_t stat_interval_{0};
  ::std::thread stats_printer_{&Analyzer::printStats, this};
};


bool loadFile(Analyzer& analyzer, const ::std::string& filename);


}  // namespace flow_inspector

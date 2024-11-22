#pragma once

#include "logger.h"
#include "events_handler.h"
#include "internal_structs.h"


namespace flow_inspector {


class Analyzer {
public:
  Analyzer(Logger& logger, EventsHandler& eventsHandler) noexcept
    : logger_{logger}
    , eventsHandler_{eventsHandler}
  {}

  void detectThreats(const internal::Packet& /*packet*/) {
    // Реализация обнаружения угроз
  }

  void loadRule(const internal::Rule& rule) {
    rules_.push_back(rule);
  }

  void loadSignature(const internal::Signature& signature) {
    signatures_.push_back(signature);
  }

private:
  ::std::vector<internal::Rule> rules_;
  ::std::vector<internal::Signature> signatures_;
  Logger& logger_;
  EventsHandler& eventsHandler_;
};


}  // namespace flow_inspector

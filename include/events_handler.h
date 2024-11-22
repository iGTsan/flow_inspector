#pragma once

#include "internal_structs.h"
#include "logger.h"


namespace flow_inspector {


class EventsHandler {
public:
  EventsHandler(Logger& logger) noexcept
    : logger_{logger}
  {}

  void sendAlert(const internal::Alert& alert) {
    logger_.logAlert(std::make_shared<internal::Alert>(alert));
    // Реализация отправки уведомления
  }

  void blockTraffic(const internal::Packet& /*packet*/) {
    // Реализация блокировки трафика
  }

  void addEvent(const internal::Event& event) {
    eventsList_.push(event);
  }
  
private:
    ::std::queue<internal::Event> eventsList_;
    Logger& logger_;
};


}  // namespace flow_inspector

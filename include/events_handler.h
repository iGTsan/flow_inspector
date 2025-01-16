#pragma once

#include <functional>
#include <unordered_map>
#include <vector>

#include "internal_structs.h"
#include "logger.h"


namespace flow_inspector {


class EventsHandler {
public:
  using EventCallback = ::std::function<void(const internal::Event&)>;

  EventsHandler(Logger& logger) noexcept
    : logger_{logger}
  {
    addEventCallback(internal::Event::EventType::Alert,
        [this](const internal::Event& event) {
          logger_.logEvent(internal::LogEntry{
            .timestamp = logger_.getTime(),
            .packet = event.packet,
            .alert = event.rule.getName(),
          });
        });
  }

  void addEventCallback(const internal::Event::EventType type, const EventCallback& callback) {
    callbacks_[type].push_back(callback);
  }

  void addEvent(const internal::Event& event) {
    for (const auto& callback : callbacks_[event.type]) {
      callback(event);
    }
  }

private:
  ::std::unordered_map<internal::Event::EventType, ::std::vector<EventCallback>> callbacks_;
  Logger& logger_;
};


}  // namespace flow_inspector

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

  EventsHandler(Logger& logger) noexcept;

  void addEventCallback(const internal::Event::EventType type, const EventCallback& callback) noexcept;

  void addEvent(const internal::Event& event) noexcept;

 private:
  ::std::unordered_map<internal::Event::EventType, ::std::vector<EventCallback>> callbacks_;
  Logger& logger_;
};


}  // namespace flow_inspector

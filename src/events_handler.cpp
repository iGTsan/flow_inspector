#include <functional>
#include <unordered_map>

#include "events_handler.h"
#include "internal_structs.h"
#include "logger.h"


namespace flow_inspector {


EventsHandler::EventsHandler(Logger& logger) noexcept
  : logger_{logger}
{
  addEventCallback(internal::Event::EventType::Alert,
      [this](const internal::Event& event) {
        logger_.logEvent(internal::LogEntry{
          .timestamp = logger_.getTime(),
          .packet = event.packet.copy(),
          .alert = event.rule.getName(),
        });
      });
}

void EventsHandler::addEventCallback(
    const internal::Event::EventType type, const EventCallback& callback) noexcept {
  callbacks_[type].push_back(callback);
}

void EventsHandler::addEvent(const internal::Event& event) noexcept {
  for (const auto& callback : callbacks_[event.type]) {
    callback(event);
  }
}


}  // namespace flow_inspector

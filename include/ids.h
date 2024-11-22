#pragma once

#include "logger.h"
#include "events_handler.h"
#include "analyzer.h"
#include "packet_processors_pool.h"


namespace flow_inspector {

class IDS {
public:
  IDS(const uint8_t numPacketProcessors) noexcept
    : pool_{analyzer_, numPacketProcessors}
  {}

private:
  Logger logger_;
  EventsHandler eventsHandler_{logger_};
  Analyzer analyzer_{logger_, eventsHandler_};
  PacketProcessorsPool pool_;
};


}  // namespace flow_inspector

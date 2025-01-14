#pragma once

#include "analyzer.h"
#include "events_handler.h"
#include "logger.h"
#include "packet_processors_pool.h"
#include "packet_origin.h"


namespace flow_inspector {

class IDS {
public:
  IDS(const uint8_t numPacketProcessors, ::std::unique_ptr<PacketOrigin> origin) noexcept
    : pool_{analyzer_, numPacketProcessors}
    , origin_{::std::move(origin)}
  {
    origin_->setProcessor([this](auto packet) {
      pool_.addPacket(::std::move(packet));
    });
  }

  void start() noexcept {
    origin_->startReading();
  }

  void stop() noexcept {
    origin_->stopReading();
  }
  
  void loadRules(const ::std::string& filename) noexcept {
    VERIFY(loadFile(analyzer_, filename), "Failed to load rules from file");
  }

  void setLogLevel(Logger::LogLevel level) noexcept {
    logger_.setLevel(level);
  }

  void setOutputFilename(const ::std::string& filename) noexcept {
    output_filename_ = filename;
  }
  
  ~IDS() noexcept {
    pool_.finish();
    logger_.logMessage("IDS stopped.");
    logger_.exportLogs(output_filename_);
  }

private:
  Logger logger_;
  EventsHandler eventsHandler_{logger_};
  Analyzer analyzer_{logger_, eventsHandler_};
  PacketProcessorsPool pool_;
  ::std::unique_ptr<PacketOrigin> origin_;

  ::std::string output_filename_{"default.log"};
};


}  // namespace flow_inspector

#pragma once

#include "analyzer.h"
#include "events_handler.h"
#include "pcap_writer.h"
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
    events_handler_.addEventCallback(internal::Event::EventType::SaveToPcap,
        [this](const internal::Event& event) {
          pcap_writer_.savePacket(event.packet);
        });
  }

  void start() noexcept {
    internal::coutInfo() << "Starting reading packets" << std::endl;
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
    logger_.setOutputFilename(filename);
  }

  void setPcapOutputFilename(const ::std::string& filename) noexcept {
    pcap_writer_.setOutputFilename(filename);
  }
  
  ~IDS() noexcept {
    pool_.finish();
    logger_.logMessage("IDS stopped.");
  }

private:
  Logger logger_;
  EventsHandler events_handler_{logger_};
  Analyzer analyzer_{logger_, events_handler_};
  PcapWriter pcap_writer_;
  PacketProcessorsPool pool_;
  ::std::unique_ptr<PacketOrigin> origin_;

};


}  // namespace flow_inspector

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
  IDS(const uint8_t numPacketProcessors, ::std::unique_ptr<PacketOrigin> origin) noexcept;

  void start() noexcept;

  void stop() noexcept;
  
  void loadRules(const ::std::string& filename) noexcept;

  void setLogLevel(Logger::LogLevel level) noexcept;

  void setStatSpeed(size_t interval) noexcept;

  void setOutputFilename(const ::std::string& filename) noexcept;

  void setPcapOutputFilename(const ::std::string& filename) noexcept;
  
  ~IDS() noexcept;

 private:
  Logger logger_;
  EventsHandler events_handler_{logger_};
  Analyzer analyzer_{logger_, events_handler_};
  PcapWriter pcap_writer_;
  PacketProcessorsPool pool_;
  ::std::unique_ptr<PacketOrigin> origin_;
};


}  // namespace flow_inspector

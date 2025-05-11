#include "analyzer.h"
#include "debug_logger.h"
#include "events_handler.h"
#include "ids.h"
#include "pcap_writer.h"
#include "logger.h"
#include "packet_processors_pool.h"
#include "packet_origin.h"


namespace flow_inspector {


IDS::IDS(const uint8_t numPacketProcessors, ::std::unique_ptr<PacketOrigin> origin) noexcept
  : pcap_writer_{origin->getLinkLayerType()}
  , pool_{analyzer_, numPacketProcessors}
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

void IDS::start() noexcept {
  internal::coutInfo() << "Starting reading packets" << std::endl;
  origin_->startReading();
}

void IDS::stop() noexcept {
  origin_->stopReading();
}

void IDS::loadRules(const ::std::string& filename) noexcept {
  VERIFY(loadFile(analyzer_, filename), "Failed to load rules from file");
}

void IDS::setLogLevel(Logger::LogLevel level) noexcept {
  logger_.setLevel(level);
}

void IDS::setStatSpeed(size_t interval) noexcept {
  analyzer_.setStatSpeed(interval);
}

void IDS::setOutputFilename(const ::std::string& filename) noexcept {
  logger_.setOutputFilename(filename);
}

void IDS::setPcapOutputFilename(const ::std::string& filename) noexcept {
  pcap_writer_.setOutputFilename(filename);
}

IDS::~IDS() noexcept {
  pool_.finish();
  logger_.logMessage("IDS stopped.");
}


}  // namespace flow_inspector

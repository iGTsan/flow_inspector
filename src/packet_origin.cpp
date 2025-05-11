#include <functional>
#include <atomic>

#include <pcap.h>

#include "internal_structs.h"
#include "debug_logger.h"
#include "packet_origin.h"


namespace flow_inspector {


void PacketOrigin::setProcessor(PacketProcessor processor) noexcept {
  packet_processor_ = ::std::move(processor);
}

void PacketOrigin::processPacket(const ::pcpp::RawPacket& packet) noexcept {
  packet_processor_(internal::Packet{packet});
}

void PacketOrigin::stopReading() noexcept {
  internal::coutDebug() << "Stopping reading" << std::endl;
  done_.store(true);
  internalStopReading();
}

bool PacketOrigin::isDoneReading() const noexcept {
  return done_.load();
}


}  // namespace flow_inspector

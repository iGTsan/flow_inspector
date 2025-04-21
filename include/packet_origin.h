#pragma once

#include <functional>
#include <vector>
#include <atomic>

#include <pcap.h>

#include "internal_structs.h"
#include "debug_logger.h"
#include "Packet.h"


namespace flow_inspector {


class PacketOrigin {
public:
  using PacketProcessor = ::std::function<void(internal::Packet)>;

  void setProcessor(PacketProcessor processor) noexcept {
    packet_processor_ = ::std::move(processor);
  }

  void processPacket(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    ::std::vector<internal::byte> payload{
        reinterpret_cast<const internal::byte*>(packet), 
        reinterpret_cast<const internal::byte*>(packet) + pkthdr->caplen};
    packet_processor_(internal::Packet{
      ::std::move(payload),
    });
  }

  void processPacket(const ::pcpp::RawPacket& packet) {
    packet_processor_(internal::Packet{packet});
  }

  virtual void startReading() noexcept = 0;

  void stopReading() noexcept {
    internal::coutDebug() << "Stopping reading" << std::endl;
    done_.store(true);
    internalStopReading();
  }

  bool isDoneReading() const noexcept {
    return done_.load();
  }

  virtual ~PacketOrigin() = default;

protected:
  virtual void internalStopReading() noexcept = 0;

private:
  PacketProcessor packet_processor_;
  ::std::atomic<bool> done_;
};


}  // namespace flow_inspector

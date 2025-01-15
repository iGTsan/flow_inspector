#pragma once

#include <functional>
#include <vector>

#include <pcap.h>

#include "internal_structs.h"
#include "debug_logger.h"


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

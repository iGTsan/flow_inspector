#pragma once

#include <functional>
#include <atomic>

#include <pcap.h>

#include "internal_structs.h"


namespace flow_inspector {


class PacketOrigin {
 public:
  using PacketProcessor = ::std::function<void(internal::Packet)>;

  void setProcessor(PacketProcessor processor) noexcept;

  void processPacket(const ::pcpp::RawPacket& packet) noexcept;

  virtual void startReading() noexcept = 0;

  virtual ::pcpp::LinkLayerType getLinkLayerType() noexcept = 0;

  void stopReading() noexcept;

  bool isDoneReading() const noexcept;

  virtual ~PacketOrigin() = default;

 protected:
  virtual void internalStopReading() noexcept = 0;

 private:
  PacketProcessor packet_processor_;
  ::std::atomic<bool> done_;
};


}  // namespace flow_inspector

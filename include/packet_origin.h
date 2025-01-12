#pragma once

#include <functional>

#include "internal_structs.h"


namespace flow_inspector {


class PacketOrigin {
public:
  using PacketProcessor = ::std::function<void(internal::Packet)>;

  void setProcessor(PacketProcessor processor) noexcept {
    packet_processor_ = ::std::move(processor);
  }

  virtual void startReading() noexcept = 0;

  virtual ~PacketOrigin() = default;

protected:
  PacketProcessor packet_processor_;
};


}  // namespace flow_inspector

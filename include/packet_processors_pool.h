#pragma once

#include "analyzer.h"


namespace flow_inspector {


class PacketProcessor {
public:
  PacketProcessor(Analyzer& analyzer) noexcept
    : analyzer_(analyzer)
  {}

  void processPacket(const internal::Packet& packet) {
    analyzer_.detectThreats(packet);
  }

private:
  Analyzer& analyzer_;
};


class PacketProcessorsPool {
public:
  PacketProcessorsPool(Analyzer& analyzer, const uint8_t num_packet_processors) noexcept
  {
    for (uint8_t i = 0; i < num_packet_processors; ++i) {
      processors_.emplace_back(analyzer);
    }
  }

  void processPacket(const internal::Packet& packet) {
    processors_[0].processPacket(packet);
  }

private:
  ::std::vector<PacketProcessor> processors_;
};


}  // namespace flow_inspector

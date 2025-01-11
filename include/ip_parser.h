#pragma once

#include <memory>

#include "internal_structs.h"


namespace flow_inspector {


class IpParser : public internal::Parser {
  public:
    void parse(const internal::Packet& packet) noexcept override {

    }

    const internal::Packet* nextLayer() noexcept override {
      return nullptr;
    }

  private:
    uint8_t ttl_;

    uint32_t src_ip_;
    uint32_t dst_ip_;
};

class IpPacket: public internal::Packet {
};


}  // namespace flow_inspector

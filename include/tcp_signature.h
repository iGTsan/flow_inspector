#pragma once

#include <memory>

#include <pcap.h>

#include "internal_structs.h"

namespace flow_inspector::internal {


class TCPSignature : public Signature {
 public:
  TCPSignature(uint16_t srcPort, uint16_t dstPort) noexcept;

  bool check(const Packet& packet) const noexcept override;

  bool operator==(const Signature& other) const noexcept override;

  size_t hash() const noexcept override;

  static ::std::unique_ptr<Signature> createTCPSignature(const ::std::string& initString) noexcept;

 private:
  static ::std::string trim(const ::std::string& str) noexcept;

  uint16_t src_port_;
  uint16_t dst_port_;
};


} // namespace flow_inspector::internal

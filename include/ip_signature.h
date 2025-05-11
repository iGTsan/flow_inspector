#pragma once

#include <unordered_set>
#include <memory>

#include <pcap.h>
#include "internal_structs.h"


#define HOME_NET_ADDR "192.168.0.0/24"


namespace flow_inspector::internal {


uint32_t swapOctets(uint32_t ip) noexcept;

uint32_t getNetworkAddress(uint32_t ip, int maskLength) noexcept;

uint32_t getMaskByLen(int maskLength) noexcept;

uint32_t ipToUInt(const ::std::string& ipStr) noexcept;

::std::string adressToString(uint32_t ip, int maskLength) noexcept;


class IPSignature: public Signature {
 public:
  IPSignature(const ::std::unordered_set<::std::pair<uint32_t, uint32_t>>& srcIpMasks,
      const ::std::unordered_set<::std::pair<uint32_t, uint32_t>>& dstIpMasks) noexcept;

  bool check(const Packet& packet) const noexcept override;

  bool operator==(const Signature& other) const noexcept override;

  size_t hash() const noexcept override;

  static ::std::unique_ptr<Signature> createIPSignature(const ::std::string& initString) noexcept;

 private:
  bool matchIPWithMasks(
      uint32_t ip, const ::std::vector<::std::pair<uint32_t, uint32_t>>& ipMasks) const noexcept;

  ::std::vector<::std::pair<uint32_t, uint32_t>> src_ip_masks_;
  ::std::vector<::std::pair<uint32_t, uint32_t>> dst_ip_masks_;
};


} // namespace flow_inspector::internal

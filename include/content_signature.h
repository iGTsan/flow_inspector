#pragma once

#include <string>
#include <memory>
#include <unordered_set>
#include <regex>

#include <pcap.h>

#include "internal_structs.h"

namespace flow_inspector::internal {


class ContentSignature : public Signature {
 private:
  enum Protocols {
    TCP,
    UDP,
    HTTP,
  };

  Protocols stringToProto(const ::std::string& proto) noexcept;

 public:
  ContentSignature(
      const ::std::string& protocol,
      const ::std::string& content,
      const ::std::unordered_set<::std::string>& flags) noexcept;

  bool check(const Packet& packet) const noexcept override;

  bool operator==(const Signature& other) const noexcept override;

  size_t hash() const noexcept override;

  static ::std::unique_ptr<Signature> createContentSignature(const ::std::string& initString) noexcept;

 private:
  Protocols protocol_;
  ::std::string content_;
  ::std::unordered_set<::std::string> flags_;
  ::std::regex_constants::syntax_option_type regex_flags_ = ::std::regex_constants::ECMAScript;

  bool extractTcpPayload(const Packet& packet, ::std::string& payload) const noexcept;

  bool extractUdpPayload(const Packet& packet, ::std::string& payload) const noexcept;
};


}  // namespace flow_inspector::internal

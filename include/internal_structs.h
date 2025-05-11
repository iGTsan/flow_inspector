#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include <pcap.h>
#include "IpAddress.h"
#include "Packet.h"

#include "RawPacket.h"


#define VERIFY(expression, message) \
  do { \
    if (!(expression)) { \
      ::std::cerr << "\nAssertion failed: (" << #expression << "), function " << __FUNCTION__ \
          << ", file " << __FILE__ << ", line " << __LINE__ << ".\n" << message << std::endl; \
      ::std::abort(); \
    } \
  } while (false)


::std::string trim(const ::std::string& str) noexcept;


namespace flow_inspector::internal {


class Signature;
class Rule;


using byte = uint8_t;


class ByteVector {
 public:
  ByteVector(::std::vector<byte> data) noexcept;

  ByteVector makeSubvector(const size_t offset, const size_t length) const noexcept;

  ::std::span<const byte>* operator->() noexcept;

  const ::std::span<const byte>* operator->() const noexcept;

  const ::std::span<const byte> operator*() const noexcept;

  bool operator==(const ByteVector& other) const noexcept;

  bool operator!=(const ByteVector& other) const noexcept;

  void print() const noexcept;

 private:
  template <typename T>
  friend struct ::std::hash;

  ::std::shared_ptr<const ::std::vector<byte>> holder_;
  ::std::span<const byte> data_;
};


ByteVector byteVectorFromPCPP(const ::pcpp::RawPacket& packet) noexcept;

::pcpp::RawPacket rawPacketFromVector(
    const ::std::vector<internal::byte>& vec, const timeval& timestamp = {}) noexcept;


struct Packet {
  Packet() noexcept;

  Packet(const ::pcpp::RawPacket& _packet, bool parse_at_init = false) noexcept;

  Packet(Packet&& other) noexcept;

  Packet& operator=(Packet&& other) noexcept;

  bool operator==(const Packet& other) const noexcept;

  bool operator!=(const Packet& other) const noexcept;

  ::std::string toString() const noexcept;

  ::std::string toShortString() const noexcept;

  void parse() noexcept;

  Packet copy() const noexcept;

  const ::pcpp::Packet& getParsedPacket() const noexcept;

  ::std::unique_ptr<::pcpp::RawPacket> packet;

 private:
  ::std::unique_ptr<::pcpp::Packet> parsed_packet;
};


class Alert {
 public:
  Alert(const ::std::string& message) noexcept;

  ::std::string toString() const noexcept;

 private:
  ::std::string message_;
};


struct LogEntry {
  const ::std::time_t timestamp;
  ::std::optional<Packet> packet{};
  ::std::optional<Alert> alert{};
  ::std::optional<::std::string> message{};
};


class Signature {
 public:
  virtual bool check(const Packet& packet) const noexcept = 0;

  virtual size_t hash() const noexcept = 0;

  virtual bool operator==(const Signature& other) const noexcept = 0;
  
  virtual ~Signature() noexcept = default;
};


struct Event {
  enum class EventType {
    Alert,
    Notify,
    SaveToPcap,
    TestEvent,
    TestEvent1,
    TestEvent2,
    InvalidEventType,
  };

  static bool isValidEventType(const std::string& event) noexcept;

  static EventType stringToEventType(const std::string& event) noexcept;

  const EventType type;
  const Rule& rule;
  const Packet& packet;
};


class Rule {
 public:
  Rule(const ::std::string& name, const Event::EventType type) noexcept;

  const ::std::string& getName() const noexcept;

  const Event::EventType& getType() const noexcept;

  void addSignature(const Signature* signature) noexcept;

  bool check(const Packet& packet) const noexcept;

  bool operator==(const Rule& other) const noexcept;

 private:
  template <typename T>
  friend struct ::std::hash;

  const ::std::string name_;
  ::std::vector<const Signature*> signatures_;
  const Event::EventType type_;
};


class Parser {
 public:
  virtual void parse(const Packet& packet) noexcept = 0;

  virtual const Packet* nextLayer() noexcept = 0;
};


bool safeStringToInt(const ::std::string& str, int& result) noexcept;


}  // namespace flow_inspector::internal


namespace std {


template<>
struct hash<::flow_inspector::internal::ByteVector> {
  size_t operator()(const ::flow_inspector::internal::ByteVector& obj) const {
    size_t hashsum = 0;
    for (const auto& b : obj.data_) {
      hashsum ^= (static_cast<int>(b)) + 0x9e3779b9 + (hashsum << 6) + (hashsum >> 2);
    }
    return hashsum;
  }
};


template<>
struct hash<::flow_inspector::internal::Signature> {
    size_t operator()(const ::flow_inspector::internal::Signature& obj) const {
      return obj.hash();
    }
};


template<>
struct hash<::flow_inspector::internal::Rule> {
  size_t operator()(const ::flow_inspector::internal::Rule& obj) const {
    size_t hashsum = hash<string>{}(obj.name_);
    for (const auto& s : obj.signatures_) {
      hashsum ^= hash<::flow_inspector::internal::Signature>{}(*s);
    }
    return hashsum;
  }
};

template <>
struct hash<pcpp::IPv4Address> {
  size_t operator()(const pcpp::IPv4Address& ip) const noexcept {
    return std::hash<uint32_t>{}(ip.toInt());
  }
};

template <>
struct hash<std::pair<uint32_t, uint32_t>> {
  size_t operator()(const std::pair<uint32_t, uint32_t>& pair) const {
    size_t hash1 = std::hash<uint32_t>{}(pair.first);
    size_t hash2 = std::hash<uint32_t>{}(pair.second);
    return hash1 ^ (hash2 << 1);
  }
};


}  // namespace std


namespace flow_inspector::internal {


struct UniquePtrSignatureHash {
    ::std::size_t operator()(const ::std::unique_ptr<Signature>& sig) const {
      return ::std::hash<Signature>()(*sig);
    }
};


struct UniquePtrSignatureEqual {
    bool operator()(
        const ::std::unique_ptr<Signature>& lhs, const ::std::unique_ptr<Signature>& rhs) const {
      return *lhs == *rhs;
    }
};


}  // namespace flow_inspector::internal

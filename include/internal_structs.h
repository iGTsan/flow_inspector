#pragma once

#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <queue>
#include <string>
#include <sstream>
#include <ctime>
#include <memory>
#include <chrono>
#include <optional>
#include <cstdint>
#include <span>
#include <cstdlib>
#include <unordered_set>


#define VERIFY(expression, message) \
  do { \
    if (!(expression)) { \
      ::std::cerr << "Assertion failed: (" << #expression << "), function " << __FUNCTION__ \
          << ", file " << __FILE__ << ", line " << __LINE__ << ".\n" << message << std::endl; \
      ::std::abort(); \
    } \
  } while (false)


namespace flow_inspector::internal {


class Signature;
class Rule;


using byte = uint8_t;


class ByteVector {
public:
  ByteVector(::std::vector<byte> data) noexcept
    : holder_{::std::make_shared<const ::std::vector<byte>>(::std::move(data))}
    , data_{holder_->data(), holder_->size()}
  {}

  ByteVector makeSubvector(const size_t offset, const size_t length) const noexcept {
    ByteVector result = *this;
    result.data_ = result.data_.subspan(offset, length);
    return result;
  }

  ::std::span<const byte>* operator->() noexcept {
    return &data_;
  }

  const ::std::span<const byte>* operator->() const noexcept {
    return &data_;
  }

  const ::std::span<const byte> operator*() const noexcept {
    return data_;
  }

  bool operator==(const ByteVector& other) const noexcept {
    return data_.size() == other.data_.size() &&
        ::std::equal(data_.begin(), data_.end(), other.data_.begin());
  }

  bool operator!=(const ByteVector& other) const noexcept {
    return !(*this == other);
  }

  void print() const noexcept {
    for (auto it = data_.begin(); it!= data_.end(); ++it) {
      std::cout << int(*it) << " ";
    }
    std::cout << "\n";
  }

private:
  template <typename T>
  friend struct ::std::hash;

  ::std::shared_ptr<const ::std::vector<byte>> holder_;
  ::std::span<const byte> data_;
};


struct Packet {
  Packet(const ByteVector& data) noexcept
    : bytes{data}
  {}

  Packet(const ::std::vector<byte>& data) noexcept
    : Packet{ByteVector{data}}
  {}

  bool operator==(const Packet& other) const noexcept {
    return bytes == other.bytes;
  }

  bool operator!=(const Packet& other) const noexcept {
    return bytes != other.bytes;
  }

  ::std::string toString() const noexcept {
    ::std::stringstream ss;
    ss << "[";
    for (auto it = bytes->begin(); it != bytes->end(); ++it) {
      if (it != bytes->begin()) {
        ss << " ";
      }
      ss << int(*it);
    }
    ss << "]";
    return ss.str();
  }

  ByteVector bytes;
  ::std::unordered_set<const Signature*> signatures;
};


class Alert {
public:
  Alert(const ::std::string& message) noexcept
    : message_{message}
  {}

  ::std::string toString() const noexcept {
    return message_;
  }

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
  Signature(::std::vector<byte> payload) noexcept
    : payload_(::std::move(payload))
  {
    payload_.print();
  }

  Signature(::std::vector<byte> payload, const uint32_t payload_offset) noexcept
    : payload_(::std::move(payload))
    , payload_offset_(payload_offset)
  {
    payload_.print();
  }

  bool check(const Packet& packet) const noexcept {
    ::std::cout << "Checking signature ";
    payload_.print();
    ::std::cout << "Packet payload ";
    packet.bytes.print();
    if (packet.signatures.contains(this)) {
      return true;
    }
    if (payload_offset_) {
      return *payload_offset_ + payload_->size() <= packet.bytes->size() &&
        ::std::equal(payload_->begin(), payload_->end(), packet.bytes->begin() + *payload_offset_);
    }
    bool result = ::std::search(packet.bytes->begin(), packet.bytes->end(),
      payload_->begin(), payload_->end()) != packet.bytes->end();
    std::cout << "Result is: " << result << std::endl;
    return result;
  }

  bool operator==(const Signature& other) const noexcept {
    if (payload_offset_ != other.payload_offset_) {
      return false;
    }
    return payload_ == other.payload_;
  }

private:
  template <typename T>
  friend struct ::std::hash;

  ByteVector payload_;
  ::std::optional<uint32_t> payload_offset_;
};


struct Event {
  enum class EventType {
    Alert,
    Notify,
    TestEvent,
    TestEvent1,
    TestEvent2,
    InvalidEventType,
  };

  static bool isValidEventType(const std::string& event) {
    return event == "Alert" ||
      event == "Notify" ||
      event == "TestEvent" ||
      event == "TestEvent1" ||
      event == "TestEvent2";
  }

  static EventType stringToEventType(const std::string& event) {
    if (event == "Alert") return EventType::Alert;
    if (event == "Notify") return EventType::Notify;
    if (event == "TestEvent") return EventType::TestEvent;
    if (event == "TestEvent1") return EventType::TestEvent1;
    if (event == "TestEvent2") return EventType::TestEvent2;
    return EventType::InvalidEventType;
  }

  const EventType type;
  const Rule& rule;
  const Packet& packet;
};


class Rule {
public:
  Rule(const ::std::string& name, const Event::EventType type) noexcept
    : name_{name}
    , type_{type}
  {}

  const ::std::string& getName() const noexcept {
    return name_;
  }

  const Event::EventType& getType() const noexcept {
    return type_;
  }

  void addSignature(const Signature* signature) noexcept {
    signatures_.insert(signature);
  }

  bool check(const Packet& packet) const noexcept {
    return!signatures_.empty() &&
      ::std::all_of(signatures_.begin(), signatures_.end(),
        [&packet](const Signature* signature) { return signature->check(packet); });
  }

  bool operator==(const Rule& other) const noexcept {
    if (name_ != other.name_) {
      return false;
    }
    return signatures_ == other.signatures_;
  }

private:
  template <typename T>
  friend struct ::std::hash;

  const ::std::string name_;
  ::std::unordered_set<const Signature*> signatures_;
  const Event::EventType type_;
};


class Parser {
public:
  virtual void parse(const Packet& packet) noexcept = 0;

  virtual const Packet* nextLayer() noexcept = 0;
};


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
      return hash<::flow_inspector::internal::ByteVector>{}(obj.payload_) ^
          (hash<optional<uint32_t>>{}(obj.payload_offset_) << 1);
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

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
#include <unordered_set>


namespace flow_inspector::internal {


using byte = uint8_t;


class ByteVector {
public:
  ByteVector(::std::vector<byte> data) noexcept
    : holder_{::std::make_shared<const std::vector<byte>>(::std::move(data))}
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

private:
  ::std::shared_ptr<const ::std::vector<byte>> holder_;
  ::std::span<const byte> data_;

};


class Signature;


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
  Signature(const ::std::vector<byte>& payload) noexcept
    : payload_(payload)
  {}

  Signature(const ::std::vector<byte>& payload, const uint32_t payload_offset) noexcept
    : payload_(payload)
    , payload_offset_(payload_offset)
  {}

  bool check(const Packet& packet) const noexcept {
    if (packet.signatures.contains(this)) {
      return true;
    }
    if (payload_offset_) {
      return *payload_offset_ + payload_->size() <= packet.bytes->size() &&
        ::std::equal(payload_->begin(), payload_->end(), packet.bytes->begin() + *payload_offset_);
    }
    return ::std::search(packet.bytes->begin(), packet.bytes->end(),
      payload_->begin(), payload_->end()) != packet.bytes->end();
  }

private:
  ByteVector payload_;
  ::std::optional<uint32_t> payload_offset_;
};


class Rule {
public:
  Rule(const ::std::string& name) noexcept
    : name_{name}
  {}

  const ::std::string& getName() const noexcept {
    return name_;
  }

  void addSignature(const Signature* signature) noexcept {
    signatures_.insert(signature);
  }

  bool check(const Packet& packet) const noexcept {
    return!signatures_.empty() &&
      std::all_of(signatures_.begin(), signatures_.end(),
        [&packet](const Signature* signature) { return signature->check(packet); });
  }

private:
  ::std::string name_;
  ::std::unordered_set<const Signature*> signatures_;
};


struct Event {
  enum class EventType {
    Alert,
    Notify,
    TestEvent,
  };

  const EventType type;
  const Rule& rule;
  const Packet& packet;
};


class Parser {
public:
  virtual void parse(const Packet& packet) noexcept = 0;

  virtual const Packet* nextLayer() noexcept = 0;
};


}  // namespace flow_inspector::internal
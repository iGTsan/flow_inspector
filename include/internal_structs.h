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

  private:
    ::std::shared_ptr<const ::std::vector<byte>> holder_;
    ::std::span<const byte> data_;

};


struct Packet {
  Packet(const ByteVector& data) noexcept
    : bytes_{data}
  {}

  Packet(const ::std::vector<byte>& data) noexcept
    : Packet{ByteVector{data}}
  {}

  ::std::string toString() const noexcept {
    ::std::stringstream ss;
    ss << "[";
    for (auto it = bytes_->begin(); it != bytes_->end(); ++it) {
      if (it != bytes_->begin()) {
        ss << " ";
      }
      ss << static_cast<int>(*it);
    }
    ss << "]";
    return ss.str();
  }

  ByteVector bytes_;
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


// время, пакет, предупреждение (опционально)
struct LogEntry {
  const ::std::time_t timestamp;
  ::std::shared_ptr<const Packet> packet;
  ::std::shared_ptr<const Alert> alert;
};


class Rule {};


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
      if (payload_offset_) {
        return *payload_offset_ + payload_.size() <= packet.bytes_->size() &&
          ::std::equal(payload_.begin(), payload_.end(), packet.bytes_->begin() + *payload_offset_);
      }
      return ::std::search(packet.bytes_->begin(), packet.bytes_->end(),
        payload_.begin(), payload_.end()) != packet.bytes_->end();
    }

  private:
    ::std::vector<byte> payload_;
    ::std::optional<uint32_t> payload_offset_;
};


class Event {};


class Parser {
  public:
    virtual void parse(const Packet& packet) noexcept = 0;

    virtual const Packet* nextLayer() noexcept = 0;
};


}  // namespace flow_inspector::internal
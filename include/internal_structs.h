#pragma once

#include <iostream>
#include <vector>
#include <fstream>
#include <queue>
#include <string>
#include <sstream>
#include <ctime>
#include <memory>
#include <chrono>
#include <cstdint>


namespace flow_inspector::internal {


class Packet {
public:
  Packet(const ::std::vector<uint8_t>& data) noexcept
    : uint8_ts_{data}
  {}

  ::std::string toString() const noexcept {
    ::std::stringstream ss;
    ss << "[";
    for (const auto& b : uint8_ts_) {
      ss << static_cast<int>(b) << " ";
    }
    ss << "]";
    return ss.str();
  }

private:
  ::std::vector<uint8_t> uint8_ts_;
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
class Signature {};
class Event {};


}  // namespace flow_inspector::internal
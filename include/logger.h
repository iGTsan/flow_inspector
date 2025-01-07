#pragma once

#include <vector>
#include <fstream>
#include <string>
#include <sstream>
#include <ctime>
#include <memory>
#include <chrono>
#include "internal_structs.h"


namespace flow_inspector {


class Logger {
public:
  void logEvent(const internal::LogEntry& entry) noexcept {
    logEntries_.push_back(entry);
  }

  void logPacket(internal::Packet packet) noexcept {
    logEvent(internal::LogEntry{
      .timestamp = getTime(),
      .packet = ::std::move(packet),
    });
  }

  void logAlert(internal::Alert alert) noexcept {
    logEvent(internal::LogEntry{
      .timestamp = getTime(),
      .alert = ::std::move(alert),
    });
  }

  void logMessage(::std::string message) noexcept {
    logEvent(internal::LogEntry{
      .timestamp = getTime(),
      .message = ::std::move(message),
    });
  }

  ::std::string exportLogs() const noexcept {
    ::std::stringstream ss;
    for (const internal::LogEntry& entry : logEntries_) {
      ss << entry.timestamp << " ";
      if (entry.packet) {
          ss << "Packet: " << entry.packet->toString() << " ";
      }
      if (entry.alert) {
          ss << "Alert: " << entry.alert->toString() << " ";
      }
      if (entry.message) {
          ss << "Message: " << *entry.message << " ";
      }
      ss << "\n";
    }
    std::cout << ss.str() << "\n";
    return ss.str();
  }

  void exportLogs(const ::std::string& filename) const noexcept {
    ::std::ofstream file(filename);
    if (file.is_open()) {
      file << exportLogs();
      file.close();
    } else {
      std::cerr << "Error opening file: " << filename << "\n";
    }
  }

  static ::std::time_t getTime() noexcept {
    return ::std::time(nullptr);
  }

private:
  ::std::vector<internal::LogEntry> logEntries_;
};


}  // namespace flow_inspector

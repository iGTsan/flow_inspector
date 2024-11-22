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

  void logPacket(::std::shared_ptr<const internal::Packet> packet) noexcept {
    logEvent(internal::LogEntry{::std::time(nullptr), packet, nullptr});
  }

  void logAlert(::std::shared_ptr<const internal::Alert> alert) noexcept {
    logEvent(internal::LogEntry{::std::time(nullptr), nullptr, alert});
  }

  ::std::string exportLog() const noexcept {
    ::std::stringstream ss;
    for (const internal::LogEntry& entry : logEntries_) {
      ss << entry.timestamp << " ";
      if (entry.packet) {
          ss << "Packet: " << entry.packet->toString() << " ";
      }
      if (entry.alert) {
          ss << "Alert: " << entry.alert->toString() << " ";
      }
      ss << "\n";
    }
    return ss.str();
  }

  void exportLogs(const ::std::string& filename) const noexcept {
    ::std::ofstream file(filename);
    if (file.is_open()) {
      file << exportLog();
      file.close();
    } else {
      std::cerr << "Error opening file: " << filename << "\n";
    }
  }

private:
  ::std::vector<internal::LogEntry> logEntries_;
};


}  // namespace flow_inspector

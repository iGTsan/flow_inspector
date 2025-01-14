#pragma once

#include <vector>
#include <fstream>
#include <string>
#include <sstream>
#include <ctime>
#include <memory>
#include <chrono>
#include "internal_structs.h"
#include "debug_logger.h"


namespace flow_inspector {


class Logger {
public:
  enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
  };

  void setLevel(LogLevel level) {
    log_level_ = level;
  }

  void logEvent(const internal::LogEntry& entry) noexcept {
    ::std::lock_guard<std::mutex> lock{log_entries_mutex_};
    log_entries_.push_back(entry);
  }

  void logPacket(internal::Packet packet) noexcept {
    if (log_level_ <= LogLevel::INFO) {
      logEvent(internal::LogEntry{
        .timestamp = getTime(),
        .packet = ::std::move(packet),
      });
    }
  }

  void logAlert(internal::Alert alert) noexcept {
    if (log_level_ <= LogLevel::WARNING) {
      logEvent(internal::LogEntry{
        .timestamp = getTime(),
        .alert = ::std::move(alert),
      });
    }
  }

  void logDebug(::std::string message) noexcept {
    if (log_level_ <= LogLevel::DEBUG) {
      logMessage(::std::move(message));
    }
  }

  void logMessage(::std::string message) noexcept {
    if (log_level_ <= LogLevel::INFO) {
      internal::coutDebug() << message << ::std::endl;
      logEvent(internal::LogEntry{
        .timestamp = getTime(),
        .message = ::std::move(message),
      });
    }
  }

  ::std::string exportLogs() const noexcept {
    ::std::stringstream ss;
    for (const internal::LogEntry& entry : log_entries_) {
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
  ::std::mutex log_entries_mutex_;
  ::std::vector<internal::LogEntry> log_entries_;
  LogLevel log_level_ = LogLevel::INFO;
};


}  // namespace flow_inspector

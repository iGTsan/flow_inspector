#pragma once

#include <vector>
#include <string>
#include <ctime>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "internal_structs.h"


namespace flow_inspector {


class Logger {
 public:
  enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
  };

  void setLevel(LogLevel level) noexcept;

  void logEvent(internal::LogEntry entry) noexcept;

  void logPacket(internal::Packet packet) noexcept;

  void logAlert(internal::Alert alert) noexcept;

  void logDebug(::std::string message) noexcept;

  void logMessage(::std::string message) noexcept;

  ::std::string exportLogs() noexcept;

  void exportLogsToFile() noexcept;

  static ::std::time_t getTime() noexcept;
  
  static ::std::string formatTimestamp(::std::time_t timestamp) noexcept;

  void setOutputFilename(const ::std::string& filename) noexcept;

  ~Logger() noexcept;

  static constexpr int DEFAULT_MAX_LOG_ENTRIES = 2000;

 private:
  void logRotator() noexcept;

  ::std::mutex log_entries_mutex_;
  ::std::condition_variable log_condition_;
  ::std::vector<internal::LogEntry> log_entries_;
  LogLevel log_level_{LogLevel::DEBUG};
  ::std::mutex file_mutex_;
  ::std::string output_filename_{""};
  bool file_openned_{false};
  bool done_{false};
  bool should_rotate_{false};
  ::std::thread log_rotator_thread_{&Logger::logRotator, this};
  size_t max_log_entries_ = DEFAULT_MAX_LOG_ENTRIES;
};


}  // namespace flow_inspector

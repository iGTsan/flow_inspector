#pragma once

#include <vector>
#include <fstream>
#include <string>
#include <sstream>
#include <ctime>
#include <memory>
#include <thread>
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

  ::std::string exportLogs() noexcept {
    ::std::stringstream ss;
    ::std::vector<internal::LogEntry> log_entries;
    {
      ::std::lock_guard<std::mutex> lock{log_entries_mutex_};
      log_entries = ::std::move(log_entries_);
    }
    for (const internal::LogEntry& entry : log_entries) {
      ss << entry.timestamp << " ";
      if (entry.packet) {
          ss << "Packet: " << entry.packet->toShortString() << " ";
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

  void exportLogsToFile() noexcept {
    ::std::lock_guard<std::mutex> lock{file_mutex_};
    if (!file_openned_) {
      ::std::ofstream file(output_filename_);
      file_openned_ = true;
    }
    ::std::ofstream file(output_filename_, ::std::ios::app);
    if (file.is_open()) {
      file << exportLogs();
      file.close();
    } else {
      ::std::cerr << "Error opening file: " << output_filename_ << "\n";
    }
  }

  static ::std::time_t getTime() noexcept {
    return ::std::time(nullptr);
  }

  void setOutputFilename(const ::std::string& filename) noexcept {
    ::std::lock_guard<std::mutex> lock{file_mutex_};
    output_filename_ = filename;
    file_openned_ = false;
  }

  ~Logger() noexcept {
    ::std::cout << "done" << std::endl;
    done_.store(true);
    log_rotator_thread_.join();
  }

  static constexpr int MAX_LOG_ENTRIES = 2000;

private:
  void logRotator() {
    size_t size;
    while (!done_.load()) {
      {
        ::std::lock_guard<std::mutex> lock{log_entries_mutex_};
        size = log_entries_.size();
      }
      if (size > MAX_LOG_ENTRIES) {
        exportLogsToFile();
      }
      ::std::this_thread::sleep_for(::std::chrono::milliseconds(100));
    }
    exportLogsToFile();
  }

  ::std::mutex log_entries_mutex_;
  ::std::vector<internal::LogEntry> log_entries_;
  LogLevel log_level_ = LogLevel::INFO;
  ::std::mutex file_mutex_;
  ::std::string output_filename_{"default.log"};
  bool file_openned_;
  ::std::atomic<bool> done_;
  ::std::thread log_rotator_thread_{&Logger::logRotator, this};
};


}  // namespace flow_inspector

#pragma once

#include <vector>
#include <fstream>
#include <string>
#include <sstream>
#include <ctime>
#include <memory>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
#include <iostream>
#include <condition_variable>
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

  void logEvent(internal::LogEntry entry) noexcept {
    {
      ::std::lock_guard<::std::mutex> lock{log_entries_mutex_};
      log_entries_.push_back(::std::move(entry));
      
      // Уведомляем поток ротации, если превышен порог
      if (log_entries_.size() >= max_log_entries_) {
        should_rotate_ = true;
      }
    }
    // Уведомляем поток ротации о новом событии
    log_condition_.notify_one();
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
      ::std::lock_guard<::std::mutex> lock{log_entries_mutex_};
      log_entries = ::std::move(log_entries_);
      // Сразу очищаем оригинальный вектор для экономии памяти
      log_entries_.clear();
      should_rotate_ = false;
    }
    for (const internal::LogEntry& entry : log_entries) {
      ss << formatTimestamp(entry.timestamp) << " ";
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
    ::std::lock_guard<::std::mutex> lock{file_mutex_};
    ::std::ofstream file;
    
    if (!file_openned_) {
      file.open(output_filename_);
      file_openned_ = true;
    } else {
      file.open(output_filename_, ::std::ios::app);
    }
    
    if (file.is_open()) {
      file << exportLogs();
      file.close();
    } else {
      ::std::cerr << "Error opening file: " << output_filename_ << "\n";
    }
  }

  static ::std::time_t getTime() noexcept {
    return std::time(nullptr);
  }
  
  // Форматирование временных меток для удобочитаемости
  static ::std::string formatTimestamp(::std::time_t timestamp) {
    char buffer[80];
    struct tm* timeinfo = localtime(&timestamp);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
    return ::std::string(buffer);
  }

  void setOutputFilename(const ::std::string& filename) noexcept {
    std::lock_guard<std::mutex> lock{file_mutex_};
    output_filename_ = filename;
    file_openned_ = false;
  }

  ~Logger() noexcept {
    ::std::cout << "Logger shutting down..." << ::std::endl;
    {
      ::std::lock_guard<::std::mutex> lock{log_entries_mutex_};
      done_ = true;
    }
    log_condition_.notify_one();
    
    if (log_rotator_thread_.joinable()) {
      log_rotator_thread_.join();
    }
    exportLogsToFile();
  }

  static constexpr int DEFAULT_MAX_LOG_ENTRIES = 2000;

 private:
  void logRotator() {
    ::std::unique_lock<std::mutex> lock{log_entries_mutex_};

    while (!done_) {
      log_condition_.wait_for(lock, ::std::chrono::seconds(10), 
          [this] { return done_ || should_rotate_; });
      if (should_rotate_ || log_entries_.size() >= max_log_entries_) {
        lock.unlock();
        exportLogsToFile();
        lock.lock();
      }
    }
  }

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

#include <vector>
#include <fstream>
#include <string>
#include <sstream>
#include <ctime>
#include <thread>
#include <chrono>
#include <mutex>
#include <iostream>
#include <condition_variable>

#include "internal_structs.h"
#include "logger.h"
#include "debug_logger.h"


namespace flow_inspector {


void Logger::setLevel(LogLevel level) noexcept {
  log_level_ = level;
}

void Logger::logEvent(internal::LogEntry entry) noexcept {
  {
    ::std::lock_guard<::std::mutex> lock{log_entries_mutex_};
    log_entries_.push_back(::std::move(entry));
    
    if (log_entries_.size() >= max_log_entries_) {
      should_rotate_ = true;
    }
  }
  log_condition_.notify_one();
}

void Logger::logPacket(internal::Packet packet) noexcept {
  if (log_level_ <= LogLevel::INFO) {
    logEvent(internal::LogEntry{
      .timestamp = getTime(),
      .packet = ::std::move(packet),
    });
  }
}

void Logger::logAlert(internal::Alert alert) noexcept {
  if (log_level_ <= LogLevel::WARNING) {
    logEvent(internal::LogEntry{
      .timestamp = getTime(),
      .alert = ::std::move(alert),
    });
  }
}

void Logger::logDebug(::std::string message) noexcept {
  if (log_level_ <= LogLevel::DEBUG) {
    logMessage(::std::move(message));
  }
}

void Logger::logMessage(::std::string message) noexcept {
  if (log_level_ <= LogLevel::INFO) {
    internal::coutDebug() << message << ::std::endl;
    logEvent(internal::LogEntry{
      .timestamp = getTime(),
      .message = ::std::move(message),
    });
  }
}

::std::string Logger::exportLogs() noexcept {
  ::std::stringstream ss;
  ::std::vector<internal::LogEntry> log_entries;
  {
    ::std::lock_guard<::std::mutex> lock{log_entries_mutex_};
    log_entries = ::std::move(log_entries_);
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

void Logger::exportLogsToFile() noexcept {
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

::std::time_t Logger::getTime() noexcept {
  return std::time(nullptr);
}

::std::string Logger::formatTimestamp(::std::time_t timestamp) noexcept {
  char buffer[80];
  struct tm* timeinfo = localtime(&timestamp);
  strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
  return ::std::string(buffer);
}

void Logger::setOutputFilename(const ::std::string& filename) noexcept {
  std::lock_guard<std::mutex> lock{file_mutex_};
  output_filename_ = filename;
  file_openned_ = false;
}

Logger::~Logger() noexcept {
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

void Logger::logRotator() noexcept {
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


}  // namespace flow_inspector

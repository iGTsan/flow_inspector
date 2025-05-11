#pragma once

#include "ids.h"


namespace flow_inspector {


class IdsCli {
 public:
  IdsCli(int argc, char **argv);
  
  void updateRules() noexcept;

  void start() noexcept;

  void stop() noexcept;

 private:
  ::std::string mode_;
  ::std::string interface_;
  ::std::string pcap_file_;
  ::std::string pcap_output_file_;
  ::std::string rules_file_;
  ::std::string output_log_file_;
  uint8_t cores_;
  size_t stat_speed_;
  ::std::optional<IDS> ids_;
  Logger::LogLevel log_level_{Logger::LogLevel::INFO};
};


}  // namespace flow_inspector

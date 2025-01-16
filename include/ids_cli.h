#pragma once

#include "cxxopts.hpp"

#include "ids.h"
#include "debug_logger.h"
#include "pcap_reader.h"
#include "traffic_capturer.h"

namespace flow_inspector {

class IdsCli {
public:
  IdsCli(int argc, char **argv) {
    ::cxxopts::Options options("IdsCli", "CLI wrapper for flow inspector");

    options.add_options()
      ("m,mode", "Operating mode: 'pcap' for file input or 'live' for real-time capture",
          ::cxxopts::value<::std::string>())
      ("i,interface", "Network interface for live mode capture (only used with live mode)",
          ::cxxopts::value<::std::string>())
      ("f,file", "Path to the PCAP file for input (applicable only in pcap mode)",
          ::cxxopts::value<::std::string>())
      ("j,cores", "Number of processor cores to utilize",
          ::cxxopts::value<uint8_t>()->default_value("1"))
      ("o,log-output", "Path to the file for logging output",
          ::cxxopts::value<::std::string>()->default_value("default.log"))
      ("w,write", "Destination PCAP file to save captured data",
          ::cxxopts::value<::std::string>()->default_value("default.pcap"))
      ("r,rules", "Path to the file containing rules for packet processing",
          ::cxxopts::value<::std::string>()->default_value(""))
      ("s,stat-speed", "Interval (in seconds) for printing capture statistics",
          ::cxxopts::value<::size_t>()->default_value("0"))
      ("log-level", "Logging to stdout verbosity level: debug or info",
          ::cxxopts::value<::std::string>()->default_value("info"))
      ("h,help", "Display this help message");
    try {
      auto result = options.parse(argc, argv);

      if (result.count("help")) {
        ::std::cout << options.help() << ::std::endl;
        exit(0);
      }

      mode_ = result["mode"].as<::std::string>();
      if (mode_ == "live") {
        if (result.count("interface")) {
          interface_ = result["interface"].as<::std::string>();
        } else {
          throw ::std::invalid_argument("Interface is required for live mode");
        }
      } else if (mode_ == "pcap") {
        if (result.count("file")) {
          pcap_file_ = result["file"].as<::std::string>();
        } else {
          throw ::std::invalid_argument("File is required for pcap mode");
        }
      } else {
        throw ::std::invalid_argument("Invalid mode, use 'live' or 'pcap'");
      }

      const auto& log_level = result["log-level"].as<::std::string>();
      if (log_level == "debug") {
        log_level_ = Logger::LogLevel::DEBUG;
        internal::getCoutLevel().enable();
      }

      cores_ = result["cores"].as<uint8_t>();
      rules_file_ = result["rules"].as<::std::string>();
      output_log_file_ = result["log-output"].as<::std::string>();
      pcap_output_file_ = result["write"].as<::std::string>();
      stat_speed_ = result["stat-speed"].as<size_t>();

    } catch (const ::cxxopts::exceptions::exception& e) {
      ::std::cout << options.help() << ::std::endl;
      ::std::cerr << "Error parsing options: " << e.what() << ::std::endl;
      exit(1);
    }
  }

  void start() noexcept {
    ::std::unique_ptr<PacketOrigin> packet_origin;
    if (mode_ == "live") {
      packet_origin = ::std::make_unique<TrafficCapturer>();
      static_cast<TrafficCapturer*>(packet_origin.get())->setInterfaceName(interface_);
    } else if (mode_ == "pcap") {
      packet_origin = ::std::make_unique<PcapReader>();
      static_cast<PcapReader*>(packet_origin.get())->setFilename(pcap_file_);
    }
    ids_.emplace(cores_, ::std::move(packet_origin));
    if (!rules_file_.empty()) {
      ids_->loadRules(rules_file_);
    }
    ids_->setOutputFilename(output_log_file_);
    ids_->setPcapOutputFilename(pcap_output_file_);
    ids_->setLogLevel(log_level_);
    ids_->setStatSpeed(stat_speed_);
    
    ids_->start();
  }

  void stop() {
    if (ids_) {
      ids_->stop();
    }
  }

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

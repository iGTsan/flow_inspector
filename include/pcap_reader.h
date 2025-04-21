#pragma once

#include <functional>
#include <filesystem>
#include <memory>
#include <iostream>

#include "events_handler.h"
#include "logger.h"
#include "packet_origin.h"

#include "PcapFileDevice.h"


namespace flow_inspector {


class PcapReader: public PacketOrigin {
 public:
  void setFilename(const ::std::string& filename) noexcept {
    input_file_ = filename;
  }

  void startReading() noexcept override {
    ::pcpp::IFileReaderDevice* reader = ::pcpp::IFileReaderDevice::getReader(input_file_);
    if (!reader->open()) {
      ::std::filesystem::path current_path = ::std::filesystem::current_path();
      ::std::cerr << "Error opening pcap file: " << input_file_ << ::std::endl;
      ::std::cerr << "Current directory is " << current_path << ::std::endl;
      delete reader;
      return;
    }

    ::pcpp::RawPacket raw_packet;
    while (reader->getNextPacket(raw_packet) && !isDoneReading()) {
      processPacket(raw_packet);
    }

    reader->close();
    delete reader;
  }

  void internalStopReading() noexcept override {}

 private:
    ::std::string input_file_;
};

}  // namespace flow_inspector

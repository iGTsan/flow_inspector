#pragma once

#include <functional>
#include <filesystem>
#include <memory>

#include "events_handler.h"
#include "logger.h"
#include "packet_origin.h"

#include <pcap.h>


namespace flow_inspector {


class PcapReader: public PacketOrigin {
public:
  void setFilename(const ::std::string& filename) noexcept {
    input_file_ = filename;
  }

  void startReading() noexcept override {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t* handle = pcap_open_offline(input_file_.c_str(), errbuf);
    if (handle == nullptr) {
        ::std::filesystem::path current_path = ::std::filesystem::current_path();
        ::std::cerr << "Error opening pcap file: " << errbuf << ::std::endl;
        ::std::cerr << "Current directory is " << current_path << ::std::endl;
        return;
    }

    const u_char* packet;
    struct pcap_pkthdr header;
    while ((packet = pcap_next(handle, &header)) != nullptr && !isDoneReading()) {
      processPacket(&header, packet);
    }

    pcap_close(handle);
  }

  void internalStopReading() noexcept override {}

private:
  ::std::string input_file_;
};


}  // namespace flow_inspector

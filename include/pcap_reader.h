#pragma once

#include <functional>
#include <filesystem>
#include <memory>

#include "logger.h"
#include "events_handler.h"
#include "internal_structs.h"

#include <pcap.h>


namespace flow_inspector {


class PcapReader {
public:
  using PacketProcessor = ::std::function<void(const internal::Packet&)>;

  void setProcessor(PacketProcessor processor) noexcept {
    packet_processor_ = ::std::move(processor);
  }

  void startReading(const ::std::string& filename) noexcept {
    inputFile_ = filename;
    isReading_ = true;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);
    if (handle == nullptr) {
        ::std::filesystem::path currentPath = ::std::filesystem::current_path();
        ::std::cerr << "Error opening pcap file: " << errbuf << ::std::endl;
        ::std::cerr << "Current directory is " << currentPath << ::std::endl;
        return;
    }

    const u_char* packet;
    struct pcap_pkthdr header;
    while ((packet = pcap_next(handle, &header)) != nullptr) {
        ::std::vector<internal::byte> payload{
            reinterpret_cast<const internal::byte*>(packet), 
            reinterpret_cast<const internal::byte*>(packet) + header.caplen};
        packet_processor_(internal::Packet{
          payload,
        });
    }

    pcap_close(handle);
    
  }
  void stopReading() noexcept {
    isReading_ = false;
  }

private:
  PacketProcessor packet_processor_;
  ::std::string inputFile_;
  bool isReading_;
};


}  // namespace flow_inspector

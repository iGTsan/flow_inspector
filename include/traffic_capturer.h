
#pragma once

#include <pcap.h>
#include <iostream>
#include <cstring>
#include "logger.h"
#include "events_handler.h"
#include "internal_structs.h"
#include "packet_origin.h"

namespace flow_inspector {

class TrafficCapturer : public PacketOrigin {
public:
  TrafficCapturer() : handle_(nullptr) {}

  ~TrafficCapturer() {
    if (handle_) {
      pcap_close(handle_);
    }
  }

  void setInterfaceName(const ::std::string& interface_name) noexcept {
    interface_name_ = interface_name;
  }

  void startReading() noexcept {
    char error_buffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 subnet_mask, ip;

    if (pcap_lookupnet(interface_name_.c_str(), &ip, &subnet_mask, error_buffer) == -1) {
      ::std::cerr << "Can't get netmask for device " << interface_name_
          << ": " << error_buffer << ::std::endl;
      ip = 0;
      subnet_mask = 0;
    }

    handle_ = pcap_open_live(interface_name_.c_str(), BUFSIZ, 1, 1000, error_buffer);
    if (handle_ == nullptr) {
      ::std::cerr << "Couldn't open device " << interface_name_
          << ": " << error_buffer << ::std::endl;
      return;
    }

    while (!isDoneReading()) {
      pcap_loop(handle_, 0, packetHandler, reinterpret_cast<u_char*>(this));
    }
  }

private:
  static void packetHandler(
      u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    auto *capturer = reinterpret_cast<TrafficCapturer*>(user_data);
    capturer->processPacket(pkthdr, packet);
  }

  ::std::string interface_name_;
  pcap_t *handle_;
};

}  // namespace flow_inspector

#pragma once

#include <pcap.h>
#include <mutex>

#include "internal_structs.h"


namespace flow_inspector {


class PcapWriter {
public:
  PcapWriter()
    : handle_(nullptr), dumper_(nullptr)
  {}

  ~PcapWriter() {
    closePcap();
  }

  void setOutputFilename(const ::std::string& filename) noexcept {
    filename_ = filename;
  }

  void savePacket(const internal::Packet& packet) noexcept {
    ::std::lock_guard<::std::mutex> lock(mutex_);
    if (!dumper_) {
        openPcap();
    }

    struct pcap_pkthdr header = packet.header;

    // Записать пакет в файл.
    pcap_dump(reinterpret_cast<u_char *>(dumper_), &header, packet.bytes->data());
  }

private:
  bool openPcap() noexcept {
    closePcap();
    handle_ = pcap_open_dead(DLT_RAW, 65535);
    if (!handle_) {
      ::std::cerr << "Error creating pcap handle\n";
      return false;
    }

    dumper_ = pcap_dump_open(handle_, filename_.c_str());
    if (!dumper_) {
      ::std::cerr << "Error opening pcap file: " << pcap_geterr(handle_) << "\n";
      pcap_close(handle_);
      return false;
    }

    return true;
  }

  void closePcap() noexcept {
      if (dumper_) {
        pcap_dump_close(dumper_);
        dumper_ = nullptr;
      }
      if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
      }
  }

  ::std::mutex mutex_;
  ::std::string filename_{"default.pcap"};
  pcap_t* handle_;
  pcap_dumper_t* dumper_;
};


}  // namespace flow_inspector

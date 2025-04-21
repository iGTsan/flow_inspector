#pragma once

#include <mutex>
#include <string>
#include "PcapFileDevice.h"
#include "RawPacket.h"

#include "internal_structs.h"


namespace flow_inspector {


class PcapWriter {
public:
  PcapWriter(::pcpp::LinkLayerType link_layer_type)
    : pcapWriter_{nullptr}
    , link_layer_type_{link_layer_type}
  {}

  ~PcapWriter() {
    closePcap();
  }

  void setOutputFilename(const ::std::string& filename) noexcept {
    ::std::lock_guard<std::mutex> lock(mutex_);
    if (filename_ != filename) {
      filename_ = filename;
      if (pcapWriter_) {
        closePcap();
        openPcap();
      }
    }
  }

  void savePacket(const internal::Packet& packet) noexcept {
    ::std::lock_guard<::std::mutex> lock(mutex_);
    if (!pcapWriter_) {
      openPcap();
    }

    if (!pcapWriter_->writePacket(packet.packet)) {
      ::std::cerr << "Error writing packet to pcap file\n";
    }
  }

private:
  bool openPcap() noexcept {
    closePcap();
    
    pcapWriter_ = new ::pcpp::PcapFileWriterDevice(filename_, link_layer_type_);

    if (!pcapWriter_->open()) {
      ::std::cerr << "Error opening pcap file: " << filename_ << "\n";
      delete pcapWriter_;
      pcapWriter_ = nullptr;
      return false;
    }

    return true;
  }

  void closePcap() noexcept {
    if (pcapWriter_) {
      pcapWriter_->close();
      delete pcapWriter_;
      pcapWriter_ = nullptr;
    }
  }

  ::std::mutex mutex_;
  ::std::string filename_{"default.pcap"};
  ::pcpp::PcapFileWriterDevice* pcapWriter_;
  ::pcpp::LinkLayerType link_layer_type_;
};

}  // namespace flow_inspector

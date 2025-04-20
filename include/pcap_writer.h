#pragma once

#include <mutex>
#include <string>
#include "PcapFileDevice.h"
#include "RawPacket.h"

#include "internal_structs.h"


namespace flow_inspector {


class PcapWriter {
public:
  PcapWriter()
    : pcapWriter_(nullptr)
  {}

  ~PcapWriter() {
    closePcap();
  }

  void setOutputFilename(const ::std::string& filename) noexcept {
    ::std::lock_guard<std::mutex> lock(mutex_);
    // Если имя файла изменилось, закрываем текущий и открываем новый
    if (filename_ != filename) {
      filename_ = filename;
      // Если уже был открыт pcap-файл, закрыть и открыть новый
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

    ::pcpp::RawPacket rawPacket(
      packet.bytes->data(),
      packet.bytes->size(),
      packet.header.ts,
      false,
      ::pcpp::LinkLayerType::LINKTYPE_DLT_RAW1
    );

    if (!pcapWriter_->writePacket(rawPacket)) {
      ::std::cerr << "Error writing packet to pcap file\n";
    }
  }

private:
  bool openPcap() noexcept {
    closePcap();
    
    pcapWriter_ = new ::pcpp::PcapFileWriterDevice(filename_, ::pcpp::LinkLayerType::LINKTYPE_DLT_RAW1);

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
};

}  // namespace flow_inspector

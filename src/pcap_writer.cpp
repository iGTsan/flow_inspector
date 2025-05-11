#include <mutex>
#include <string>

#include "PcapFileDevice.h"
#include "RawPacket.h"

#include "internal_structs.h"
#include "pcap_writer.h"


namespace flow_inspector {


PcapWriter::PcapWriter(::pcpp::LinkLayerType link_layer_type) noexcept
  : pcapWriter_{nullptr}
  , link_layer_type_{link_layer_type}
{}

PcapWriter::~PcapWriter() noexcept {
  closePcap();
}

void PcapWriter::setOutputFilename(const ::std::string& filename) noexcept {
  ::std::lock_guard<std::mutex> lock(mutex_);
  if (filename_ != filename) {
    filename_ = filename;
    if (pcapWriter_) {
      closePcap();
      openPcap();
    }
  }
}

void PcapWriter::savePacket(const internal::Packet& packet) noexcept {
  ::std::lock_guard<::std::mutex> lock(mutex_);
  if (!pcapWriter_) {
    openPcap();
  }

  if (!pcapWriter_->writePacket(*packet.packet)) {
    ::std::cerr << "Error writing packet to pcap file\n";
  }
}

bool PcapWriter::openPcap() noexcept {
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

void PcapWriter::closePcap() noexcept {
  if (pcapWriter_) {
    pcapWriter_->close();
    delete pcapWriter_;
    pcapWriter_ = nullptr;
  }
}


}  // namespace flow_inspector

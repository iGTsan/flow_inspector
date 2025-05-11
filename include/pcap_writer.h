#pragma once

#include <mutex>
#include <string>

#include "PcapFileDevice.h"
#include "RawPacket.h"

#include "internal_structs.h"


namespace flow_inspector {


class PcapWriter {
 public:
  PcapWriter(::pcpp::LinkLayerType link_layer_type) noexcept;

  ~PcapWriter() noexcept;

  void setOutputFilename(const ::std::string& filename) noexcept;

  void savePacket(const internal::Packet& packet) noexcept;

 private:
  bool openPcap() noexcept;

  void closePcap() noexcept;

  ::std::mutex mutex_;
  ::std::string filename_{"default.pcap"};
  ::pcpp::PcapFileWriterDevice* pcapWriter_;
  ::pcpp::LinkLayerType link_layer_type_;
};


}  // namespace flow_inspector

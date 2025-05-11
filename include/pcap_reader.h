#pragma once

#include "RawPacket.h"

#include "packet_origin.h"


namespace flow_inspector {


class PcapReader: public PacketOrigin {
 public:
  void setFilename(const ::std::string& filename) noexcept;

  void startReading() noexcept override;

  void internalStopReading() noexcept override;

  ::pcpp::LinkLayerType getLinkLayerType() noexcept override;

 private:
    ::std::string input_file_;
};


}  // namespace flow_inspector

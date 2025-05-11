#pragma once

#include <string>

#include <PcapLiveDeviceList.h>
#include <PcapLiveDevice.h>

#include "packet_origin.h"


namespace flow_inspector {


class TrafficCapturer : public PacketOrigin {
 public:
  TrafficCapturer() noexcept;

  ~TrafficCapturer() noexcept;

  void setInterfaceName(const ::std::string& interface_name) noexcept;

  void startReading() noexcept override;

  void internalStopReading() noexcept override;

  ::pcpp::LinkLayerType getLinkLayerType() noexcept override;

 private:
  static void onPacketArrives(
      ::pcpp::RawPacket* raw_packet, ::pcpp::PcapLiveDevice* dev, void* user_data) noexcept;

  ::std::string interface_name_;
  ::pcpp::PcapLiveDevice* device_;
};


}  // namespace flow_inspector

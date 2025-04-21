#pragma once

#include <PcapLiveDeviceList.h>
#include <PcapLiveDevice.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include "logger.h"
#include "events_handler.h"
#include "internal_structs.h"
#include "packet_origin.h"


namespace flow_inspector {


class TrafficCapturer : public PacketOrigin {
public:
  TrafficCapturer() : device_(nullptr) {}

  ~TrafficCapturer() {
    if (device_) {
      device_->stopCapture();
    }
  }

  void setInterfaceName(const ::std::string& interface_name) noexcept {
    interface_name_ = interface_name;
  }

  void startReading() noexcept override {
    device_ = ::pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_name_);
    if (device_ == nullptr) {
      ::std::cerr << "Couldn't find device " << interface_name_ << ::std::endl;
      return;
    }
    
    if (!device_->open()) {
      ::std::cerr << "Couldn't open device " << interface_name_ << ::std::endl;
      return;
    }

    device_->startCapture(onPacketArrives, this);

    // Wait for reading to complete
    while (!isDoneReading()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    device_->stopCapture();
    device_->close();
  }

  void internalStopReading() noexcept override {
    if (device_) {
      device_->stopCapture();
    }
  }

private:
  static void onPacketArrives(::pcpp::RawPacket* rawPacket, ::pcpp::PcapLiveDevice* /*dev*/, void* userData) {
    auto* capturer = reinterpret_cast<TrafficCapturer*>(userData);
    capturer->processPacket(*rawPacket);
  }

  ::std::string interface_name_;
  ::pcpp::PcapLiveDevice* device_;
};

}  // namespace flow_inspector

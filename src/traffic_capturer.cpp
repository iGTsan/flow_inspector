#include <iostream>
#include <string>
#include <thread>
#include <chrono>

#include <PcapLiveDeviceList.h>
#include <PcapLiveDevice.h>

#include "traffic_capturer.h"


namespace flow_inspector {


TrafficCapturer::TrafficCapturer() noexcept : device_(nullptr) {}

TrafficCapturer::~TrafficCapturer() noexcept {
  if (device_) {
    device_->stopCapture();
  }
}

void TrafficCapturer::setInterfaceName(const ::std::string& interface_name) noexcept {
  interface_name_ = interface_name;
}

void TrafficCapturer::startReading() noexcept {
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

  while (!isDoneReading()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  device_->stopCapture();
  device_->close();
}

void TrafficCapturer::internalStopReading() noexcept {
  if (device_) {
    device_->stopCapture();
  }
}

::pcpp::LinkLayerType TrafficCapturer::getLinkLayerType() noexcept {
  device_ = ::pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_name_);
  if (device_ == nullptr) {
    ::std::cerr << "Couldn't find device " << interface_name_ << ::std::endl;
    return ::pcpp::LinkLayerType::LINKTYPE_DLT_RAW1;
  }
  
  if (!device_->open()) {
    ::std::cerr << "Couldn't open device " << interface_name_ << ::std::endl;
    return ::pcpp::LinkLayerType::LINKTYPE_DLT_RAW1;
  }

  return device_->getLinkType();
}

void TrafficCapturer::onPacketArrives(
    ::pcpp::RawPacket* raw_packet, ::pcpp::PcapLiveDevice* /*dev*/, void* user_data) noexcept {
  auto* capturer = reinterpret_cast<TrafficCapturer*>(user_data);
  capturer->processPacket(*raw_packet);
}


}  // namespace flow_inspector

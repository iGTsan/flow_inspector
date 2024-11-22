#pragma once

#include "logger.h"
#include "events_handler.h"
#include "internal_structs.h"


namespace flow_inspector {


class TrafficCapture {
public:
  void startCapture(const ::std::string& iface) {
    interfaceName_ = iface;
    isCapturing_ = true;
    // Реализация захвата трафика
  }
  void stopCapture() {
    isCapturing_ = false;
  }
  void saveCapture(const ::std::string& /*filenamee*/) {
    // Реализация сохранения захвата
  }

private:
  std::string interfaceName_;
  bool isCapturing_;
};


}  // namespace flow_inspector

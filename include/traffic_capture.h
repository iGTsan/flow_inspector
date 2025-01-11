#pragma once

#include "logger.h"
#include "events_handler.h"
#include "internal_structs.h"


namespace flow_inspector {


class TrafficCapture {
public:
  void startCapture(const ::std::string& iface) {
    interface_name_ = iface;
    is_capturing_ = true;
    // Реализация захвата трафика
  }
  void stopCapture() {
    is_capturing_ = false;
  }
  void saveCapture(const ::std::string& /*filenamee*/) {
    // Реализация сохранения захвата
  }

private:
  std::string interface_name_;
  bool is_capturing_;
};


}  // namespace flow_inspector

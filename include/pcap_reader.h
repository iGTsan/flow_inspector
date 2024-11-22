#pragma once

#include "logger.h"
#include "events_handler.h"
#include "internal_structs.h"


namespace flow_inspector {


class PcapReader {
public:
  void startReading(const ::std::string& filename) {
    inputFile_ = filename;
    isReading_ = true;
    // Реализация чтения из файла
  }
  void stopReading() {
    isReading_ = false;
  }

private:
  ::std::string inputFile_;
  bool isReading_;
};


}  // namespace flow_inspector

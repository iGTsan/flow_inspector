#include <filesystem>
#include <iostream>

#include "RawPacket.h"
#include "PcapFileDevice.h"

#include "pcap_reader.h"


namespace flow_inspector {


void PcapReader::setFilename(const ::std::string& filename) noexcept {
  input_file_ = filename;
}

void PcapReader::startReading() noexcept {
  ::pcpp::IFileReaderDevice* reader = ::pcpp::IFileReaderDevice::getReader(input_file_);
  if (!reader->open()) {
    ::std::filesystem::path current_path = ::std::filesystem::current_path();
    ::std::cerr << "Error opening pcap file: " << input_file_ << ::std::endl;
    ::std::cerr << "Current directory is " << current_path << ::std::endl;
    delete reader;
    return;
  }

  ::pcpp::RawPacket raw_packet;
  while (reader->getNextPacket(raw_packet) && !isDoneReading()) {
    processPacket(raw_packet);
  }

  reader->close();
  delete reader;
}

void PcapReader::internalStopReading() noexcept {}

::pcpp::LinkLayerType PcapReader::getLinkLayerType() noexcept {
  ::pcpp::PcapFileReaderDevice reader{input_file_};
  if (!reader.open()) {
    ::std::filesystem::path current_path = ::std::filesystem::current_path();
    ::std::cerr << "Error opening pcap file: " << input_file_ << ::std::endl;
    ::std::cerr << "Current directory is " << current_path << ::std::endl;
    return ::pcpp::LinkLayerType::LINKTYPE_DLT_RAW1;
  }
  return reader.getLinkLayerType();
}


}  // namespace flow_inspector

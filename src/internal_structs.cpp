#include <cstring>
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>
#include <ctime>
#include <memory>
#include <span>
#include <cstdlib>

#include <pcap.h>

#include "Packet.h"
#include "RawPacket.h"

#include "debug_logger.h"
#include "internal_structs.h"


::std::string trim(const ::std::string& str) noexcept {
  auto start = str.begin();
  while (start != str.end() && ::std::isspace(*start)) {
      start++;
  }

  auto end = str.end();
  do {
      end--;
  } while (::std::distance(start, end) > 0 && ::std::isspace(*end));

  return ::std::string(start, end + 1);
}


namespace flow_inspector::internal {


ByteVector::ByteVector(::std::vector<byte> data) noexcept
  : holder_{::std::make_shared<const ::std::vector<byte>>(::std::move(data))}
  , data_{holder_->data(), holder_->size()}
{}

ByteVector ByteVector::makeSubvector(const size_t offset, const size_t length) const noexcept {
  ByteVector result = *this;
  result.data_ = result.data_.subspan(offset, length);
  return result;
}

::std::span<const byte>* ByteVector::operator->() noexcept {
  return &data_;
}

const ::std::span<const byte>* ByteVector::operator->() const noexcept {
  return &data_;
}

const ::std::span<const byte> ByteVector::operator*() const noexcept {
  return data_;
}

bool ByteVector::operator==(const ByteVector& other) const noexcept {
  return data_.size() == other.data_.size() &&
      ::std::equal(data_.begin(), data_.end(), other.data_.begin());
}

bool ByteVector::operator!=(const ByteVector& other) const noexcept {
  return !(*this == other);
}

void ByteVector::print() const noexcept {
  for (auto it = data_.begin(); it!= data_.end(); ++it) {
    coutDebug() << int(*it) << " ";
  }
  coutDebug() << "\n";
}


ByteVector byteVectorFromPCPP(const ::pcpp::RawPacket& packet) noexcept {
  const u_char* raw_data = packet.getRawData();
  size_t length = packet.getRawDataLen();

  return ByteVector(::std::vector<byte>(raw_data, raw_data + length));
}

::pcpp::RawPacket rawPacketFromVector(
    const ::std::vector<internal::byte>& vec, const timeval& timestamp) noexcept {
  size_t length = vec.size();
  const u_char* raw_data = vec.data();

  timeval time_stamp_copy = timestamp;

  if (time_stamp_copy.tv_sec == 0 && time_stamp_copy.tv_usec == 0) {
    gettimeofday(&time_stamp_copy, nullptr);
  }

  return ::pcpp::RawPacket(raw_data, length, time_stamp_copy, false);
}


Packet::Packet() noexcept {}

Packet::Packet(const ::pcpp::RawPacket& _packet, bool parse_at_init) noexcept
    : packet{::std::make_unique<::pcpp::RawPacket>(_packet)}
{
  if (parse_at_init) {
    parse();
  }
}

Packet::Packet(Packet&& other) noexcept
  : packet{::std::move(other.packet)}
  , parsed_packet{::std::move(other.parsed_packet)}
{}

Packet& Packet::operator=(Packet&& other) noexcept {
  if (this != &other) {
    packet = ::std::move(other.packet);
    parsed_packet = ::std::move(other.parsed_packet);
  }
  return *this;
}

bool Packet::operator==(const Packet& other) const noexcept {
  return (packet->getRawDataLen() == other.packet->getRawDataLen() &&
    ::memcmp(packet->getRawData(), other.packet->getRawData(), packet->getRawDataLen()) == 0);
}

bool Packet::operator!=(const Packet& other) const noexcept {
  return !(*this == other);
}

::std::string Packet::toString() const noexcept {
  ::std::stringstream ss;
  ss << "[";
  const u_char* rawData = packet->getRawData();
  size_t length = packet->getRawDataLen();
  for (size_t i = 0; i < length; ++i) {
    if (i != 0) {
      ss << " ";
    }
    ss << int(rawData[i]);
  }
  ss << "]";
  return ss.str();
}

::std::string Packet::toShortString() const noexcept {
  if (packet->getRawDataLen() < 10) {
    return toString();
  }
  return "";
}

void Packet::parse() noexcept {
  if (!parsed_packet) {
    parsed_packet = ::std::make_unique<::pcpp::Packet>(packet.get());
  }
  VERIFY(parsed_packet, "Can't parse packet");
}

Packet Packet::copy() const noexcept {
  return Packet{*packet};
}

const ::pcpp::Packet& Packet::getParsedPacket() const noexcept {
  VERIFY(parsed_packet, "Can't parse packet");
  return *parsed_packet;
}


Alert::Alert(const ::std::string& message) noexcept
  : message_{message}
{}

::std::string Alert::toString() const noexcept {
  return message_;
}


bool Event::isValidEventType(const std::string& event) noexcept {
  return event == "Alert" ||
    event == "Notify" ||
    event == "SaveToPcap" ||
    event == "TestEvent" ||
    event == "TestEvent1" ||
    event == "TestEvent2";
}

Event::EventType Event::stringToEventType(const std::string& event) noexcept {
  if (event == "Alert") return EventType::Alert;
  if (event == "Notify") return EventType::Notify;
  if (event == "SaveToPcap") return EventType::SaveToPcap;
  if (event == "TestEvent") return EventType::TestEvent;
  if (event == "TestEvent1") return EventType::TestEvent1;
  if (event == "TestEvent2") return EventType::TestEvent2;
  return EventType::InvalidEventType;
}


Rule::Rule(const ::std::string& name, const Event::EventType type) noexcept
  : name_{name}
  , type_{type}
{}

const ::std::string& Rule::getName() const noexcept {
  return name_;
}

const Event::EventType& Rule::getType() const noexcept {
  return type_;
}

void Rule::addSignature(const Signature* signature) noexcept {
  signatures_.push_back(signature);
}

bool Rule::check(const Packet& packet) const noexcept {
  for (const auto& sig: signatures_) {
    if (!sig->check(packet)) {
      return false;
    }
  }
  return true;
}

bool Rule::operator==(const Rule& other) const noexcept {
  if (name_ != other.name_) {
    return false;
  }
  return signatures_ == other.signatures_;
}


bool safeStringToInt(const ::std::string& str, int& result) noexcept {
  ::std::istringstream iss(str);
  iss >> result;
  return !iss.fail() && iss.eof();
}


}  // namespace flow_inspector::internal

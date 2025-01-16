#pragma once

#include <thread>
#include <unordered_set>

#include "logger.h"
#include "events_handler.h"
#include "internal_structs.h"


namespace flow_inspector {


class Analyzer {
public:
  Analyzer(Logger& logger, EventsHandler& events_handler) noexcept
    : logger_{logger}
    , events_handler_{events_handler}
  {}

  void detectThreats(const internal::Packet& packet) {
    packets_count_.fetch_add(1);
    // logger_.logDebug("detectThreats for " + packet.toString());
    for (const auto&  rule : rules_) {
      if (rule.check(packet)) {
        events_handler_.addEvent(internal::Event{
          .type = rule.getType(),
          .rule = rule,
          .packet = packet,
        });
        logger_.logDebug("Threat detected");
      }
    }
  }

  bool parseRule(const ::std::string& rule) {
    return tryParseNative(rule);
  }

  size_t getSignaturesCount() const {
    return signatures_.size();
  }

  void setStatSpeed(size_t interval) noexcept {
    done_.store(true);
    if (stats_printer_.joinable()) {
      stats_printer_.join();
    }
    done_.store(false);
    stat_interval_ = interval;
    stats_printer_ = ::std::thread{&Analyzer::printStats, this};
  }

  ~Analyzer() noexcept {
    done_.store(true);
    if (stats_printer_.joinable()) {
      stats_printer_.join();
    }
  }

private:
  // parses the rules that satisfy the following pattern
  // event; name; signature1; signature2 ...
  // where event is a member of ::flow_inspector::internal::Event::EventType
  // signature1 is (payload, offset) or just (payload)
  // payload is a vector bytes [1 2 3...], offset is a uint32_t
  bool tryParseNative(const ::std::string& rule) {
    ::std::istringstream stream(rule);
    ::std::string event_str;

    if (!::std::getline(stream, event_str, ';')) {
      internal::coutDebug() <<
          rule + " rule doesn't contains event";
      return false;
    }
    ::std::string name;
    if (!::std::getline(stream, name, ';')) {
      internal::coutDebug() <<
          rule + " rule doesn't contains name";
      return false;
    }
    if (!internal::Event::isValidEventType(event_str)) {
      internal::coutDebug() <<
          rule + " rule contains invalid event";
      return false;
    }

    internal::Rule result(name, internal::Event::stringToEventType(event_str));
    ::std::string signature;
    while (std::getline(stream, signature, ';')) {
      size_t open_bracket = signature.find('(');
      size_t close_bracket = signature.find(')', open_bracket);
      if (open_bracket == ::std::string::npos || close_bracket == ::std::string::npos) {
        internal::coutDebug() <<
            rule + " \"" + signature + "\" signature contains wrong brackets";
        return false;
      }

      ::std::string payload_str =
          signature.substr(open_bracket + 1, close_bracket - open_bracket - 1);
      ::std::istringstream payload_stream(payload_str);
      ::std::string item;
      ::std::vector<::std::string> components;

      while (::std::getline(payload_stream, item, ',')) {
        components.push_back(item);
      }
      if (components.size() != 1 && components.size() != 2) {
        internal::coutDebug() << rule + " \"" + signature
            + "\" signature contains wrong number of components: " << components.size();
        return false;
      }
      
      ::std::vector<internal::byte> payload;
      ::std::istringstream byte_stream(components[0]);
      char bracket;
      byte_stream >> bracket;
      int byte_value;
      while (byte_stream >> byte_value) {
        if (byte_value < 0 || byte_value > 255) {
          internal::coutDebug() <<
              rule + " \"" + signature + "\" signature contains wrong byte";
          return false;
        }
        internal::coutDebug() << rule + " \"" + signature + "\" \"" +::std::to_string(byte_value) +
            "\" payload contains byte";
        payload.push_back(internal::byte(byte_value & 0xFF));
      }

      if (payload.size() == 0) {
        internal::coutDebug() <<
            rule + " \"" + signature + "\" signature contains no payload";
        return false;
      }

      ::std::optional<uint32_t> offset;
      if (components.size() == 2) {
        offset = static_cast<uint32_t>(::std::stoi(components[1]));
        internal::coutDebug() << rule + " \"" + signature + "\" \"" + ::std::to_string(*offset) +
            "\" payload contains offset";
      }

      const internal::Signature* sig;
      if (offset) {
        const auto& it = signatures_.insert(
            ::std::make_unique<internal::Signature>(payload, *offset)).first;
        sig = it->get();
      } else {
        const auto& it = signatures_.insert(
            ::std::make_unique<internal::Signature>(payload)).first;
        sig = it->get();
      }
      result.addSignature(sig);
    }

    loadRule(::std::move(result));
    return true;
  }

  void loadRule(internal::Rule rule) {
    rules_.insert(::std::move(rule));
  }

  void printStats() {
    size_t current_count;
    while (!done_.load() && stat_interval_) {
      current_count = packets_count_.exchange(0);
      internal::coutInfo()
          << "Current speed: " << current_count << " packets per second" << std::endl;
      ::std::this_thread::sleep_for(std::chrono::seconds(stat_interval_));
    }
  }

  ::std::unordered_set<internal::Rule> rules_;
  ::std::unordered_set<
      ::std::unique_ptr<internal::Signature>,
      internal::UniquePtrSignatureHash,
      internal::UniquePtrSignatureEqual> signatures_;
  Logger& logger_;
  EventsHandler& events_handler_;
  ::std::atomic<size_t> packets_count_;
  ::std::atomic<bool> done_{false};
  ::std::size_t stat_interval_{0};
  ::std::thread stats_printer_{&Analyzer::printStats, this};
};


inline bool loadFile(Analyzer& analyzer, const std::string& filename) {
  internal::coutInfo() << "Starting reading rules" << std::endl;
  size_t cnt = 0;
  ::std::ifstream file(filename);
  if (!file.is_open()) {
    ::std::cerr << "Can't open file " << filename << std::endl;
    return false;
  }
  ::std::string line;
  while (std::getline(file, line)) {
    if (!analyzer.parseRule(line)) {
      return false;
    }
    cnt++;
  }
  internal::coutInfo() << "Successfully read " << cnt << " rules" << std::endl;
  return true;
}


}  // namespace flow_inspector

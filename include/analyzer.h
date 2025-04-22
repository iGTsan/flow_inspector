#pragma once

#include <thread>
#include <unordered_set>

#include "ip_signature.h"
#include "tcp_signature.h"
#include "content_signature.h"
#include "logger.h"
#include "events_handler.h"
#include "internal_structs.h"
#include "raw_bytes_signature.h"


namespace flow_inspector {


class Analyzer {
public:
  Analyzer(Logger& logger, EventsHandler& events_handler) noexcept
    : logger_{logger}
    , events_handler_{events_handler}
  {
    internal::SignatureFactory::instance().registerSignatureType(
        "raw_bytes", internal::RawBytesSignature::createRawBytesSignature);
    internal::SignatureFactory::instance().registerSignatureType(
        "ip", internal::IPSignature::createIPSignature);
    internal::SignatureFactory::instance().registerSignatureType(
        "tcp", internal::TCPSignature::createTCPSignature);
    internal::SignatureFactory::instance().registerSignatureType(
        "content", internal::ContentSignature::createContentSignature);
  }

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

    ::std::string signature;
    internal::Rule result(name, internal::Event::stringToEventType(event_str));
    while (::std::getline(stream, signature, ';')) {
      signature = trim(signature);
      if (signature.empty()) {
        continue;
      }
      size_t open_bracket = signature.find('(');
      size_t close_bracket = signature.find(')', open_bracket);
      if (open_bracket == ::std::string::npos || close_bracket == ::std::string::npos) {
        internal::coutDebug() <<
            rule + " \"" + signature + "\" signature contains wrong brackets";
        return false;
      }

      ::std::string type = trim(signature.substr(0, open_bracket));
      ::std::string initString = signature.substr(open_bracket + 1, close_bracket - open_bracket - 1);

      auto uniq_sig = internal::SignatureFactory::instance().createSignature(type, initString);
      if (!uniq_sig) {
        internal::coutDebug() <<
            rule + " \"" + signature + "\" unsupported signature type \"" + type + "\"\n";
        return false;
      }
      const auto& it = signatures_.insert(::std::move(uniq_sig)).first;
      auto sig = it->get();
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

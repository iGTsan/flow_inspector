#include <thread>
#include <unordered_set>
#include <shared_mutex>
#include <mutex>
#include <fstream>

#include "analyzer.h"
#include "debug_logger.h"
#include "ip_signature.h"
#include "tcp_signature.h"
#include "content_signature.h"
#include "logger.h"
#include "events_handler.h"
#include "internal_structs.h"
#include "raw_bytes_signature.h"
#include "signature_factory.h"


namespace flow_inspector {


Analyzer::Analyzer(Logger& logger, EventsHandler& events_handler) noexcept
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

void Analyzer::detectThreats(const internal::Packet& packet) noexcept {
  packets_count_.fetch_add(1);
  
  ::std::shared_lock<::std::shared_mutex> lock(rules_mutex_);
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

bool Analyzer::parseRule(const ::std::string& rule) noexcept {
  return tryParseNative(rule);
}

size_t Analyzer::getSignaturesCount() const noexcept {
  ::std::shared_lock<::std::shared_mutex> lock(rules_mutex_);
  return signatures_.size();
}

void Analyzer::setStatSpeed(size_t interval) noexcept {
  done_.store(true);
  if (stats_printer_.joinable()) {
    stats_printer_.join();
  }
  done_.store(false);
  stat_interval_ = interval;
  stats_printer_ = ::std::thread{&Analyzer::printStats, this};
}

bool Analyzer::updateRulesFromFile(const ::std::string& filename) noexcept {
  logger_.logMessage("Updating rules from file: " + filename);
  
  ::std::unordered_set<internal::Rule> new_rules;
  ::std::unordered_set<
      ::std::unique_ptr<internal::Signature>,
      internal::UniquePtrSignatureHash,
      internal::UniquePtrSignatureEqual> new_signatures;
  
  if (!parseRulesFile(filename, new_rules, new_signatures)) {
    logger_.logMessage("Failed to parse rules file: " + filename);
    return false;
  }
  
  ::std::unique_lock<::std::shared_mutex> lock(rules_mutex_);
  
  rules_ = ::std::move(new_rules);
  signatures_ = ::std::move(new_signatures);
  
  logger_.logMessage("Rules successfully updated. Total rules: " + ::std::to_string(rules_.size()));
  return true;
}

Analyzer::~Analyzer() noexcept {
  done_.store(true);
  if (stats_printer_.joinable()) {
    stats_printer_.join();
  }
}

bool Analyzer::parseRulesFile(
    const ::std::string& filename,
    ::std::unordered_set<internal::Rule>& rules_container,
    ::std::unordered_set<
        ::std::unique_ptr<internal::Signature>,
        internal::UniquePtrSignatureHash,
        internal::UniquePtrSignatureEqual>& signatures_container) noexcept {
  
  internal::coutInfo() << "Starting reading rules from " << filename << ::std::endl;
  ::std::ifstream file(filename);
  if (!file.is_open()) {
    return false;
  }
  
  size_t cnt = 0;
  ::std::string line;
  while (::std::getline(file, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    
    if (!parseRuleToContainer(line, rules_container, signatures_container)) {
      return false;
    }
    cnt++;
  }
  
  internal::coutInfo() << "Successfully read " << cnt << " rules" << ::std::endl;
  return true;
}

bool Analyzer::parseRuleToContainer(
    const ::std::string& rule,
    ::std::unordered_set<internal::Rule>& rules_container,
    ::std::unordered_set<
        ::std::unique_ptr<internal::Signature>,
        internal::UniquePtrSignatureHash,
        internal::UniquePtrSignatureEqual>& signatures_container) noexcept {
  
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
    const auto& it = signatures_container.insert(::std::move(uniq_sig)).first;
    auto sig = it->get();
    result.addSignature(sig);
  }

  rules_container.insert(::std::move(result));
  return true;
}

bool Analyzer::tryParseNative(const ::std::string& rule) noexcept {
  ::std::unique_lock<::std::shared_mutex> lock(rules_mutex_);
  return parseRuleToContainer(rule, rules_, signatures_);
}

void Analyzer::loadRule(internal::Rule rule) noexcept {
  ::std::unique_lock<::std::shared_mutex> lock(rules_mutex_);
  rules_.insert(::std::move(rule));
}

void Analyzer::printStats() noexcept {
  size_t current_count;
  while (!done_.load() && stat_interval_) {
    current_count = packets_count_.exchange(0);
    internal::coutInfo()
        << "Current speed: " << current_count << " packets per second" << ::std::endl;
    ::std::this_thread::sleep_for(::std::chrono::seconds(stat_interval_));
  }
}

bool loadFile(Analyzer& analyzer, const ::std::string& filename) {
  return analyzer.updateRulesFromFile(filename);
}


}  // namespace flow_inspector

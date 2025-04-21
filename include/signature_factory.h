#include <iostream>
#include <sstream>
#include <unordered_map>
#include <functional>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include "internal_structs.h"


namespace flow_inspector::internal {


class SignatureFactory {
public:
  using SignatureCreator = std::function<std::unique_ptr<Signature>(const ::std::string&)>;
  
  static SignatureFactory& instance() {
    static SignatureFactory factory;
    return factory;
  }

  void registerSignatureType(const std::string& type, SignatureCreator creator) {
    creators_[type] = creator;
  }

  std::unique_ptr<internal::Signature> createSignature(
      const std::string& type, const std::string& initString) const {
    auto it = creators_.find(type);
    if (it != creators_.end()) {
      return (it->second)(initString);
    }
    return nullptr;
  }

private:
  std::unordered_map<std::string, SignatureCreator> creators_;
};


} // namespace flow_inspector::internal

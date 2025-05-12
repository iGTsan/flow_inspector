#include <unordered_map>
#include <functional>
#include <string>
#include <memory>

#include "internal_structs.h"
#include "signature_factory.h"


namespace flow_inspector::internal {


SignatureFactory& SignatureFactory::instance() noexcept {
  static SignatureFactory factory;
  return factory;
}

void SignatureFactory::registerSignatureType(const ::std::string& type, SignatureCreator creator) noexcept {
  creators_[type] = creator;
}

::std::unique_ptr<internal::Signature> SignatureFactory::createSignature(
    const ::std::string& type, const ::std::string& initString) const noexcept {
  auto it = creators_.find(type);
  if (it != creators_.end()) {
    return (it->second)(initString);
  }
  return nullptr;
}


}  // namespace flow_inspector::internal

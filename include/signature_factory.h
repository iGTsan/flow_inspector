#pragma once

#include <unordered_map>
#include <functional>
#include <string>
#include <memory>

#include "internal_structs.h"


namespace flow_inspector::internal {


class SignatureFactory {
 public:
  using SignatureCreator = std::function<std::unique_ptr<Signature>(const ::std::string&)>;
  
  static SignatureFactory& instance() noexcept;

  void registerSignatureType(const std::string& type, SignatureCreator creator) noexcept;

  std::unique_ptr<internal::Signature> createSignature(
      const std::string& type, const std::string& initString) const noexcept;

 private:
  std::unordered_map<std::string, SignatureCreator> creators_;
};


} // namespace flow_inspector::internal

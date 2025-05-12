#pragma once

#include <unordered_map>
#include <functional>
#include <string>
#include <memory>

#include "internal_structs.h"


namespace flow_inspector::internal {


/**
 * @class SignatureFactory
 * @brief Фабрика для создания различных типов сигнатур обнаружения угроз.
 * 
 * Реализует паттерн проектирования "Фабричный метод" (Factory Method),
 * предоставляющий централизованный механизм для создания объектов сигнатур 
 * различных типов на основе их идентификаторов и параметров инициализации.
 * Использует синглтон для глобального доступа к фабрике.
 */
class SignatureFactory {
 public:
  /**
   * @typedef SignatureCreator
   * @brief Функтор для создания конкретного типа сигнатуры.
   * 
   * Принимает строку инициализации с параметрами сигнатуры
   * и возвращает созданный объект сигнатуры заданного типа.
   */
  using SignatureCreator = ::std::function<::std::unique_ptr<Signature>(const ::std::string&)>;

  /**
   * @brief Возвращает единственный экземпляр фабрики сигнатур (синглтон).
   * @return Ссылка на экземпляр фабрики.
   */
  static SignatureFactory& instance() noexcept;
  
  /**
   * @brief Регистрирует новый тип сигнатуры с соответствующим создателем.
   * @param type Идентификатор типа сигнатуры (например, "ip", "tcp", "content").
   * @param creator Функция-создатель для данного типа сигнатуры.
   * 
   * Позволяет динамически расширять систему новыми типами сигнатур
   * без модификации кода фабрики.
   */
  void registerSignatureType(const ::std::string& type, SignatureCreator creator) noexcept;
  
  /**
   * @brief Создает сигнатуру указанного типа по строке инициализации.
   * @param type Тип создаваемой сигнатуры.
   * @param initString Строка с параметрами инициализации сигнатуры.
   * @return Указатель на созданную сигнатуру или nullptr, если тип не зарегистрирован.
   * 
   * Ищет зарегистрированный создатель для указанного типа и делегирует
   * ему создание сигнатуры на основе переданных параметров.
   */
  ::std::unique_ptr<internal::Signature> createSignature(
     const ::std::string& type, const ::std::string& initString) const noexcept;

 private:
  /**
   * @brief Хранилище зарегистрированных создателей сигнатур.
   * 
   * Ключ - идентификатор типа сигнатуры, значение - функция-создатель.
   */
  ::std::unordered_map<::std::string, SignatureCreator> creators_;
};


}  // namespace flow_inspector::internal

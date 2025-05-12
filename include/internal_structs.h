#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include <pcap.h>

#include "IpAddress.h"
#include "Packet.h"
#include "RawPacket.h"

/**
 * @brief Макрос для проверки условий во время выполнения с выводом сообщения об ошибке
 * @param expression Проверяемое выражение
 * @param message Сообщение, которое будет выведено в случае несоблюдения условия
 */
#define VERIFY(expression, message) \
do { \
  if (!(expression)) { \
    ::std::cerr << "\nAssertion failed: (" << #expression << "), function " << __FUNCTION__ \
               << ", file " << __FILE__ << ", line " << __LINE__ << ".\n" << message << std::endl; \
    ::std::abort(); \
  } \
} while (false)

/**
 * @brief Удаляет пробельные символы с начала и конца строки
 * @param str Исходная строка
 * @return Строка без начальных и конечных пробелов
 */
::std::string trim(const ::std::string& str) noexcept;


namespace flow_inspector::internal {


class Signature;
class Rule;

/**
 * @brief Тип для представления байта данных
 */
using byte = uint8_t;


/**
 * @class ByteVector
 * @brief Класс для безопасной работы с последовательностью байтов
 *
 * Обеспечивает общий доступ к памяти через std::shared_ptr для предотвращения
 * излишнего копирования данных, когда это возможно.
 */
class ByteVector {
 public:
  /**
   * @brief Создает ByteVector из вектора байтов
   * @param data Исходный вектор байтов
   */
  ByteVector(::std::vector<byte> data) noexcept;
  
  /**
   * @brief Создает новый ByteVector, содержащий подмножество текущего вектора
   * @param offset Начальная позиция подмножества
   * @param length Длина подмножества
   * @return Новый ByteVector с указанным подмножеством
   */
  ByteVector makeSubvector(const size_t offset, const size_t length) const noexcept;
  
  /**
   * @brief Оператор доступа к span через указатель
   * @return Указатель на span байтов
   */
  ::std::span<const byte>* operator->() noexcept;
  
  /**
   * @brief Константный оператор доступа к span через указатель
   * @return Константный указатель на span байтов
   */
  const ::std::span<const byte>* operator->() const noexcept;
  
  /**
   * @brief Оператор разыменования для получения span байтов
   * @return Span байтов
   */
  const ::std::span<const byte> operator*() const noexcept;
  
  /**
   * @brief Оператор сравнения для ByteVector
   * @param other Другой ByteVector для сравнения
   * @return true если векторы равны, иначе false
   */
  bool operator==(const ByteVector& other) const noexcept;
  
  /**
   * @brief Оператор неравенства для ByteVector
   * @param other Другой ByteVector для сравнения
   * @return true если векторы не равны, иначе false
   */
  bool operator!=(const ByteVector& other) const noexcept;
  
  /**
   * @brief Выводит содержимое вектора в отладочный поток
   */
  void print() const noexcept;
  
 private:
  template <typename T>
  friend struct ::std::hash;
  
  ::std::shared_ptr<const ::std::vector<byte>> holder_; ///< Владелец данных
  ::std::span<const byte> data_; ///< Область просмотра данных
};


/**
 * @brief Создает ByteVector из сырого пакета pcpp
 * @param packet Сырой пакет
 * @return ByteVector, содержащий данные пакета
 */
ByteVector byteVectorFromPCPP(const ::pcpp::RawPacket& packet) noexcept;


/**
 * @brief Создает сырой пакет pcpp из вектора байтов
 * @param vec Вектор байтов
 * @param timestamp Временная метка пакета (по умолчанию текущее время)
 * @return Сырой пакет pcpp
 */
::pcpp::RawPacket rawPacketFromVector(
    const ::std::vector<internal::byte>& vec, const timeval& timestamp = {}) noexcept;


/**
 * @class Packet
 * @brief Представляет сетевой пакет с возможностью анализа его содержимого
 */
struct Packet {
  /**
   * @brief Создает пустой пакет
   */
  Packet() noexcept;
  
  /**
   * @brief Создает пакет из сырого пакета pcpp
   * @param _packet Сырой пакет
   * @param parse_at_init Флаг, указывающий, нужно ли сразу анализировать пакет
   */
  Packet(const ::pcpp::RawPacket& _packet, bool parse_at_init = false) noexcept;
  
  /**
   * @brief Перемещающий конструктор
   * @param other Другой пакет
   */
  Packet(Packet&& other) noexcept;
  
  /**
   * @brief Перемещающий оператор присваивания
   * @param other Другой пакет
   * @return Ссылка на текущий пакет
   */
  Packet& operator=(Packet&& other) noexcept;
  
  /**
   * @brief Оператор сравнения пакетов
   * @param other Другой пакет
   * @return true если пакеты идентичны, иначе false
   */
  bool operator==(const Packet& other) const noexcept;
  
  /**
   * @brief Оператор неравенства пакетов
   * @param other Другой пакет
   * @return true если пакеты различны, иначе false
   */
  bool operator!=(const Packet& other) const noexcept;
  
  /**
   * @brief Преобразует пакет в строку для отображения
   * @return Строковое представление пакета
   */
  ::std::string toString() const noexcept;
  
  /**
   * @brief Сокращенное строковое представление пакета
   * @return Сокращенная строка для больших пакетов
   */
  ::std::string toShortString() const noexcept;
  
  /**
   * @brief Анализирует пакет, создавая его структурное представление
   */
  void parse() noexcept;
  
  /**
   * @brief Создает копию пакета
   * @return Новый пакет, являющийся копией текущего
   */
  Packet copy() const noexcept;
  
  /**
   * @brief Получает проанализированную версию пакета
   * @return Ссылка на объект анализа пакета
   */
  const ::pcpp::Packet& getParsedPacket() const noexcept;
  
  ::std::unique_ptr<::pcpp::RawPacket> packet; ///< Сырые данные пакета
  
 private:
  ::std::unique_ptr<::pcpp::Packet> parsed_packet; ///< Проанализированная структура пакета
};


/**
 * @class Alert
 * @brief Представляет предупреждение безопасности
 */
class Alert {
 public:
  /**
   * @brief Создает предупреждение с указанным сообщением
   * @param message Текст предупреждения
   */
  Alert(const ::std::string& message) noexcept;
  
  /**
   * @brief Преобразует предупреждение в строку
   * @return Строковое представление предупреждения
   */
  ::std::string toString() const noexcept;
  
 private:
  ::std::string message_; ///< Текст предупреждения
};


/**
 * @struct LogEntry
 * @brief Запись в журнале событий
 */
struct LogEntry {
  const ::std::time_t timestamp; ///< Временная метка события
  ::std::optional<Packet> packet{}; ///< Связанный с событием пакет (если есть)
  ::std::optional<Alert> alert{}; ///< Предупреждение (если есть)
  ::std::optional<::std::string> message{}; ///< Текстовое сообщение (если есть)
};


/**
 * @class Signature
 * @brief Базовый абстрактный класс для сигнатур обнаружения угроз
 */
class Signature {
 public:
  /**
   * @brief Проверяет, соответствует ли пакет данной сигнатуре
   * @param packet Проверяемый пакет
   * @return true если пакет удовлетворяет сигнатуре, иначе false
   */
  virtual bool check(const Packet& packet) const noexcept = 0;
  
  /**
   * @brief Вычисляет хеш сигнатуры для быстрого сравнения и хранения
   * @return Хеш-значение сигнатуры
   */
  virtual size_t hash() const noexcept = 0;
  
  /**
   * @brief Сравнивает сигнатуры
   * @param other Другая сигнатура
   * @return true если сигнатуры эквивалентны, иначе false
   */
  virtual bool operator==(const Signature& other) const noexcept = 0;
  
  /**
   * @brief Виртуальный деструктор для корректного удаления наследников
   */
  virtual ~Signature() noexcept = default;
};


/**
 * @struct Event
 * @brief Событие безопасности, обнаруженное системой
 */
struct Event {
  /**
   * @enum EventType
   * @brief Типы событий безопасности
   */
  enum class EventType {
    Alert, ///< Тревога о потенциальной угрозе
    Notify, ///< Информационное уведомление
    SaveToPcap, ///< Сохранение пакета для дальнейшего анализа
    TestEvent, ///< Тестовое событие
    TestEvent1, ///< Тестовое событие 1
    TestEvent2, ///< Тестовое событие 2
    InvalidEventType, ///< Недопустимый тип события
  };
  
  /**
   * @brief Проверяет, является ли строка допустимым типом события
   * @param event Строковое представление типа события
   * @return true если тип события допустим, иначе false
   */
  static bool isValidEventType(const std::string& event) noexcept;
  
  /**
   * @brief Преобразует строку в тип события
   * @param event Строковое представление типа события
   * @return Соответствующий тип события или InvalidEventType
   */
  static EventType stringToEventType(const std::string& event) noexcept;
  
  const EventType type; ///< Тип события
  const Rule& rule; ///< Правило, вызвавшее событие
  const Packet& packet; ///< Пакет, связанный с событием
};


/**
 * @class Rule
 * @brief Правило обнаружения угроз, содержащее одну или несколько сигнатур
 */
class Rule {
 public:
  /**
   * @brief Создает правило с указанным именем и типом события
   * @param name Имя правила
   * @param type Тип события, генерируемого при срабатывании правила
   */
  Rule(const ::std::string& name, const Event::EventType type) noexcept;
  
  /**
   * @brief Получает имя правила
   * @return Имя правила
   */
  const ::std::string& getName() const noexcept;
  
  /**
   * @brief Получает тип события, генерируемого правилом
   * @return Тип события
   */
  const Event::EventType& getType() const noexcept;
  
  /**
   * @brief Добавляет сигнатуру к правилу
   * @param signature Указатель на сигнатуру
   */
  void addSignature(const Signature* signature) noexcept;
  
  /**
   * @brief Проверяет, удовлетворяет ли пакет всем сигнатурам правила
   * @param packet Проверяемый пакет
   * @return true если пакет соответствует всем сигнатурам, иначе false
   */
  bool check(const Packet& packet) const noexcept;
  
  /**
   * @brief Оператор сравнения правил
   * @param other Другое правило
   * @return true если правила идентичны, иначе false
   */
  bool operator==(const Rule& other) const noexcept;
  
 private:
  template <typename T>
  friend struct ::std::hash;
  
  const ::std::string name_; ///< Имя правила
  ::std::vector<const Signature*> signatures_; ///< Сигнатуры, входящие в правило
  const Event::EventType type_; ///< Тип события при срабатывании
};


/**
 * @class Parser
 * @brief Абстрактный базовый класс для парсеров различных протоколов
 */
class Parser {
 public:
  /**
   * @brief Анализирует пакет
   * @param packet Анализируемый пакет
   */
  virtual void parse(const Packet& packet) noexcept = 0;

  /**
   * @brief Переходит к следующему уровню протокола
   * @return Указатель на пакет следующего уровня или nullptr
   */
  virtual const Packet* nextLayer() noexcept = 0;
};


/**
 * @brief Безопасно преобразует строку в целое число
 * @param str Исходная строка
 * @param result Переменная для сохранения результата
 * @return true если преобразование успешно, иначе false
 */
bool safeStringToInt(const ::std::string& str, int& result) noexcept;


}  // namespace flow_inspector::internal


namespace std {


/**
 * @brief Специализация хеш-функции для ByteVector
 */
template<>
struct hash<::flow_inspector::internal::ByteVector> {
  size_t operator()(const ::flow_inspector::internal::ByteVector& obj) const {
    size_t hashsum = 0;
    for (const auto& b : obj.data_) {
      hashsum ^= (static_cast<int>(b)) + 0x9e3779b9 + (hashsum << 6) + (hashsum >> 2);
    }
    return hashsum;
  }
};


/**
 * @brief Специализация хеш-функции для Signature
 */
template<>
struct hash<::flow_inspector::internal::Signature> {
  size_t operator()(const ::flow_inspector::internal::Signature& obj) const {
    return obj.hash();
  }
};


/**
 * @brief Специализация хеш-функции для Rule
 */
template<>
struct hash<::flow_inspector::internal::Rule> {
  size_t operator()(const ::flow_inspector::internal::Rule& obj) const {
    size_t hashsum = hash<string>{}(obj.name_);
    for (const auto& s : obj.signatures_) {
      hashsum ^= hash<::flow_inspector::internal::Signature>{}(*s);
    }
    return hashsum;
  }
};

/**
 * @brief Специализация хеш-функции для IPv4Address
 */
template <>
struct hash<pcpp::IPv4Address> {
  size_t operator()(const pcpp::IPv4Address& ip) const noexcept {
    return std::hash<uint32_t>{}(ip.toInt());
  }
};


/**
 * @brief Специализация хеш-функции для пары uint32_t значений
 */
template <>
struct hash<std::pair<uint32_t, uint32_t>> {
  size_t operator()(const std::pair<uint32_t, uint32_t>& pair) const {
    size_t hash1 = std::hash<uint32_t>{}(pair.first);
    size_t hash2 = std::hash<uint32_t>{}(pair.second);
    return hash1 ^ (hash2 << 1);
  }
};


}  // namespace std


namespace flow_inspector::internal {


/**
 * @struct UniquePtrSignatureHash
 * @brief Хеш-функция для std::unique_ptr<Signature>
 */
struct UniquePtrSignatureHash {
  ::std::size_t operator()(const ::std::unique_ptr<Signature>& sig) const {
    return ::std::hash<Signature>()(*sig);
  }
};


/**
 * @struct UniquePtrSignatureEqual
 * @brief Функция сравнения для std::unique_ptr<Signature>
 */
struct UniquePtrSignatureEqual {
  bool operator()(
    const ::std::unique_ptr<Signature>& lhs, const ::std::unique_ptr<Signature>& rhs) const {
    return *lhs == *rhs;
  }
};


}  // namespace flow_inspector::internal

#pragma once

#include <thread>
#include <unordered_set>
#include <shared_mutex>

#include "logger.h"
#include "events_handler.h"
#include "internal_structs.h"


namespace flow_inspector {


/**
 * @class Analyzer
 * @brief Ядро системы обнаружения вторжений, отвечающее за анализ трафика и сопоставление с правилами.
 *
 * Класс осуществляет обработку сетевых пакетов, сравнивая их с заданными правилами (сигнатурами)
 * для выявления подозрительной активности. Поддерживает различные типы сигнатур, такие как
 * raw_bytes, ip, tcp, content и может быть расширен для поддержки других типов.
 */
class Analyzer {
 public:
  /**
   * @brief Конструктор анализатора трафика.
   * @param logger Система логирования для записи событий.
   * @param events_handler Обработчик событий для генерации уведомлений.
   */
  Analyzer(Logger& logger, EventsHandler& events_handler) noexcept;

  /**
   * @brief Анализирует пакет на наличие угроз, сравнивая с загруженными правилами.
   * @param packet Сетевой пакет для анализа.
   * 
   * Основной метод обработки пакетов, проверяет каждый пакет на соответствие всем правилам.
   * При обнаружении совпадения с правилом, генерирует соответствующее событие.
   */
  void detectThreats(const internal::Packet& packet) noexcept;

  /**
   * @brief Анализирует и загружает правило в формате строки.
   * @param rule Строка с правилом в формате "событие;имя;сигнатура1;сигнатура2;...".
   * @return true в случае успешной загрузки, false при ошибке парсинга.
   */
  bool parseRule(const ::std::string& rule) noexcept;

  /**
   * @brief Возвращает количество загруженных сигнатур.
   * @return Количество уникальных сигнатур в системе.
   */
  size_t getSignaturesCount() const noexcept;

  /**
   * @brief Устанавливает интервал вывода статистики обработки пакетов.
   * @param interval Интервал в секундах. 0 для отключения вывода статистики.
   */
  void setStatSpeed(size_t interval) noexcept;

  /**
   * @brief Обновляет правила из указанного файла.
   * @param filename Путь к файлу правил.
   * @return true в случае успешной загрузки, false при ошибке.
   * 
   * Полностью заменяет текущий набор правил на новые из файла.
   */
  bool updateRulesFromFile(const ::std::string& filename) noexcept;

  /**
   * @brief Деструктор. Завершает работу потока статистики.
   */
  ~Analyzer() noexcept;

 private:
  /**
   * @brief Парсит правила из файла в указанные контейнеры.
   * @param filename Путь к файлу с правилами.
   * @param rules_container Контейнер для загрузки правил.
   * @param signatures_container Контейнер для загрузки сигнатур.
   * @return true в случае успешной загрузки, false при ошибке.
   */
  bool parseRulesFile(
      const ::std::string& filename,
      ::std::unordered_set<internal::Rule>& rules_container,
      ::std::unordered_set<
          ::std::unique_ptr<internal::Signature>,
          internal::UniquePtrSignatureHash,
          internal::UniquePtrSignatureEqual>& signatures_container) noexcept;

  /**
   * @brief Парсит одно правило в строковом формате и добавляет в контейнеры.
   * @param rule Строка с правилом.
   * @param rules_container Контейнер для загрузки правил.
   * @param signatures_container Контейнер для загрузки сигнатур.
   * @return true в случае успешного парсинга, false при ошибке.
   */
  bool parseRuleToContainer(
      const ::std::string& rule,
      ::std::unordered_set<internal::Rule>& rules_container,
      ::std::unordered_set<
          ::std::unique_ptr<internal::Signature>,
          internal::UniquePtrSignatureHash,
          internal::UniquePtrSignatureEqual>& signatures_container) noexcept;

  /**
   * @brief Парсит нативное правило в строковом формате в текущие контейнеры.
   * @param rule Строка с правилом.
   * @return true в случае успешного парсинга, false при ошибке.
   */
  bool tryParseNative(const ::std::string& rule) noexcept;

  /**
   * @brief Загружает уже готовое правило в анализатор.
   * @param rule Объект правила.
   */
  void loadRule(internal::Rule rule) noexcept;

  /**
   * @brief Потоковая функция для вывода статистики обработки пакетов.
   * 
   * Периодически выводит количество обработанных пакетов в заданном интервале.
   */
  void printStats() noexcept;

  mutable ::std::shared_mutex rules_mutex_; ///< Мьютекс для безопасного доступа к правилам
  ::std::unordered_set<internal::Rule> rules_; ///< Набор правил для обнаружения угроз
  ::std::unordered_set<
      ::std::unique_ptr<internal::Signature>,
      internal::UniquePtrSignatureHash,
      internal::UniquePtrSignatureEqual> signatures_; ///< Набор уникальных сигнатур

  Logger& logger_; ///< Система логирования
  EventsHandler& events_handler_; ///< Обработчик событий
  ::std::atomic<size_t> packets_count_; ///< Счетчик обработанных пакетов для статистики
  ::std::atomic<bool> done_{false}; ///< Флаг завершения работы
  ::std::size_t stat_interval_{0}; ///< Интервал вывода статистики в секундах

  ::std::thread stats_printer_{&Analyzer::printStats, this}; ///< Поток вывода статистики
};


/**
 * @brief Вспомогательная функция для загрузки правил из файла в анализатор.
 * @param analyzer Экземпляр анализатора.
 * @param filename Путь к файлу с правилами.
 * @return true в случае успешной загрузки, false при ошибке.
 */
bool loadFile(Analyzer& analyzer, const ::std::string& filename);


}  // namespace flow_inspector

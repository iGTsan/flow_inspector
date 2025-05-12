#pragma once

#include "analyzer.h"
#include "events_handler.h"
#include "pcap_writer.h"
#include "logger.h"
#include "packet_processors_pool.h"
#include "packet_origin.h"


namespace flow_inspector {


/**
 * @class IDS
 * @brief Intrusion Detection System - основной класс системы обнаружения вторжений.
 * 
 * Класс объединяет компоненты обработки и анализа сетевого трафика, события
 * и логирование для обнаружения потенциальных угроз безопасности.
 */
class IDS {
public:
  /**
   * @brief Конструктор системы обнаружения вторжений.
   * @param numPacketProcessors Количество обработчиков пакетов для параллельной обработки трафика.
   * @param origin Источник сетевого трафика (pcap-файл или сетевой интерфейс).
   */
  IDS(const uint8_t numPacketProcessors, ::std::unique_ptr<PacketOrigin> origin) noexcept;
  
  /**
   * @brief Запускает захват и анализ пакетов.
   * 
   * Начинает мониторинг трафика из указанного источника 
   * и запускает обработку с применением правил обнаружения.
   */
  void start() noexcept;
  
  /**
   * @brief Останавливает захват и анализ пакетов.
   */
  void stop() noexcept;
  
  /**
   * @brief Загружает правила обнаружения из указанного файла.
   * @param filename Путь к файлу с правилами.
   */
  void loadRules(const ::std::string& filename) noexcept;
  
  /**
   * @brief Устанавливает уровень детализации логирования.
   * @param level Уровень логирования (DEBUG, INFO, WARNING, ERROR).
   */
  void setLogLevel(Logger::LogLevel level) noexcept;
  
  /**
   * @brief Устанавливает интервал вывода статистики работы анализатора.
   * @param interval Интервал в секундах. 0 для отключения статистики.
   */
  void setStatSpeed(size_t interval) noexcept;
  
  /**
   * @brief Устанавливает имя файла для сохранения журнала событий.
   * @param filename Путь к файлу для записи журнала.
   */
  void setOutputFilename(const ::std::string& filename) noexcept;
  
  /**
   * @brief Устанавливает имя файла для сохранения перехваченных пакетов.
   * @param filename Путь к файлу .pcap для записи пакетов.
   */
  void setPcapOutputFilename(const ::std::string& filename) noexcept;
  
  /**
   * @brief Деструктор. Завершает работу анализаторов и освобождает ресурсы.
   */
  ~IDS() noexcept;

 private:
  Logger logger_; /// Система журналирования событий и предупреждений
  EventsHandler events_handler_{logger_}; /// Обработчик событий безопасности
  Analyzer analyzer_{logger_, events_handler_}; /// Анализатор трафика и правил
  PcapWriter pcap_writer_; /// Модуль сохранения подозрительных пакетов
  PacketProcessorsPool pool_; /// Пул обработчиков пакетов
  ::std::unique_ptr<PacketOrigin> origin_; /// Источник сетевого трафика
};


}  // namespace flow_inspector

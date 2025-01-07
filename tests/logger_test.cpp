#include <gtest/gtest.h>
#include "logger.h"


namespace flow_inspector {


TEST(LoggerTest, LogPacketEvent) {
  Logger logger;
  internal::Packet testPacket{::std::vector<internal::byte>{1, 2, 3, 4}};

  logger.logPacket(testPacket);

  ::std::string exportedLog = logger.exportLogs();
  EXPECT_TRUE(exportedLog.find("Packet: [1 2 3 4]") != ::std::string::npos);
}

TEST(LoggerTest, LogAlertEvent) {
  Logger logger;
  auto testAlert = internal::Alert{"Test alert message"};

  logger.logAlert(testAlert);

  ::std::string exportedLog = logger.exportLogs();
  EXPECT_TRUE(exportedLog.find("Alert: Test alert message") != ::std::string::npos);
}


TEST(LoggerTest, ExportEmptyLogEntries) {
  Logger logger;

  ::std::string exportedLog = logger.exportLogs();
  EXPECT_TRUE(exportedLog.empty());

  ::std::string tempFileName = "temp_empty_log.txt";
  logger.exportLogs(tempFileName);

  ::std::ifstream file(tempFileName);
  EXPECT_TRUE(file.is_open());
  
  ::std::string fileContent((std::istreambuf_iterator<char>(file)),
      std::istreambuf_iterator<char>());
  EXPECT_TRUE(fileContent.empty());

  file.close();
  ::std::remove(tempFileName.c_str());
}

TEST(LoggerTest, ExportLogsToFile) {
  Logger logger;
  internal::Packet testPacket{::std::vector<internal::byte>{1, 2, 3, 4}};
  auto testAlert = internal::Alert{"Test alert message"};

  logger.logPacket(testPacket);
  logger.logAlert(testAlert);

  ::std::string tempFileName = "temp_log.txt";
  logger.exportLogs(tempFileName);

  ::std::ifstream file(tempFileName);
  ASSERT_TRUE(file.is_open());
  ::std::string fileContent((::std::istreambuf_iterator<char>(file)),
      ::std::istreambuf_iterator<char>());

  EXPECT_TRUE(fileContent.find("Packet: [1 2 3 4]") != ::std::string::npos);
  EXPECT_TRUE(fileContent.find("Alert: Test alert message") != ::std::string::npos);

  file.close();
  ::std::remove(tempFileName.c_str());
}


TEST(LoggerTest, HandleLargeNumberOfLogEntries) {
  Logger logger;
  const int numEntries = 10;
  // const int numEntries = 1000000;

  for (int i = 0; i < numEntries; ++i) {
    if (i % 2 == 0) {
      internal::Packet packet{::std::vector<internal::byte>{1, 2, 3, 4}};
      logger.logPacket(packet);
    } else {
      auto alert = internal::Alert{"Test alert message"};
      logger.logAlert(alert);
    }
  }

  ::std::string exportedLog = logger.exportLogs();

  size_t packetCount = 0;
  size_t alertCount = 0;
  size_t pos = 0;
  while ((pos = exportedLog.find("Packet:", pos)) != ::std::string::npos) {
    ++packetCount;
    pos += 7;
  }
  pos = 0;
  while ((pos = exportedLog.find("Alert:", pos)) != ::std::string::npos) {
    ++alertCount;
    pos += 6;
  }

  EXPECT_EQ(packetCount, numEntries / 2);
  EXPECT_EQ(alertCount, numEntries / 2);
}


}  // namespace flow_inspector

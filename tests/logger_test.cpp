#include <gtest/gtest.h>
#include "logger.h"


namespace flow_inspector {


TEST(LoggerTest, LogPacketEvent) {
  Logger logger;
  internal::Packet testPacket{internal::rawPacketFromVector(::std::vector<internal::byte>{1, 2, 3, 4})};

  logger.logPacket(::std::move(testPacket));

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
  logger.setOutputFilename(tempFileName);
  logger.exportLogsToFile();

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
  internal::Packet testPacket{internal::rawPacketFromVector(::std::vector<internal::byte>{1, 2, 3, 4})};
  auto testAlert = internal::Alert{"Test alert message"};

  logger.logPacket(::std::move(testPacket));
  logger.logAlert(testAlert);

  ::std::string tempFileName = "temp_log.txt";
  logger.setOutputFilename(tempFileName);
  logger.exportLogsToFile();

  ::std::ifstream file(tempFileName);
  ASSERT_TRUE(file.is_open());
  ::std::string fileContent((::std::istreambuf_iterator<char>(file)),
      ::std::istreambuf_iterator<char>());

  EXPECT_TRUE(fileContent.find("Packet: [1 2 3 4]") != ::std::string::npos) << fileContent;
  EXPECT_TRUE(fileContent.find("Alert: Test alert message") != ::std::string::npos);

  file.close();
  ::std::remove(tempFileName.c_str());
}


TEST(LoggerTest, HandleLargeNumberOfLogEntries) {
  Logger logger;
  const int numEntries = 1000;

  for (int i = 0; i < numEntries; ++i) {
    if (i % 2 == 0) {
      internal::Packet packet{internal::rawPacketFromVector(::std::vector<internal::byte>{1, 2, 3, 4})};
      logger.logPacket(::std::move(packet));
    } else {
      auto alert = internal::Alert{"Test alert message"};
      logger.logAlert(alert);
    }
  }

  ::std::cout << "before export" << std::endl;
  ::std::string exportedLog = logger.exportLogs();
  ::std::cout << "after export" << std::endl;

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


TEST(LoggerTest, LogRotationWhenMaxEntriesExceeded) {
  Logger logger;
  const ::std::string tempFileName = "temp_rotated_log.txt";
  
  logger.setOutputFilename(tempFileName);

  for (int i = 0; i <= Logger::DEFAULT_MAX_LOG_ENTRIES; ++i) {
    internal::Packet packet{internal::rawPacketFromVector(
        ::std::vector<internal::byte>{static_cast<internal::byte>(i)})};
    logger.logPacket(::std::move(packet));
  }

  ::std::this_thread::sleep_for(::std::chrono::milliseconds(10));

  for (int i = 0; i < Logger::DEFAULT_MAX_LOG_ENTRIES - 100; ++i) {
    internal::Packet packet{internal::rawPacketFromVector(
        ::std::vector<internal::byte>{static_cast<internal::byte>(i)})};
    logger.logPacket(::std::move(packet));
  }

  ::std::ifstream file(tempFileName);
  ASSERT_TRUE(file.is_open());

  ::std::string fileContent((::std::istreambuf_iterator<char>(file)),
      ::std::istreambuf_iterator<char>());

  EXPECT_FALSE(fileContent.empty());

  int logEntryCount = 0;
  size_t pos = 0;
  while ((pos = fileContent.find("Packet:", pos)) != ::std::string::npos) {
    ++logEntryCount;
    pos += 7;
  }
  EXPECT_LE(logEntryCount, Logger::DEFAULT_MAX_LOG_ENTRIES + 1);

  file.close();
  ::std::remove(tempFileName.c_str());
}


TEST(LoggerTest, SetOutputFilename) {
  Logger logger;
  ::std::string newFilename = "new_output.log";

  logger.setOutputFilename(newFilename);
  logger.exportLogsToFile();

  ::std::ifstream file(newFilename);
  ASSERT_TRUE(file.is_open());
  file.close();

  ::std::remove(newFilename.c_str());
}


TEST(LoggerTest, DestructorBehavior) {
  {
    Logger logger;
    logger.setOutputFilename("test_destructor.log");
    
    for (int i = 0; i < 100; ++i) {
      logger.logMessage("Test message " + ::std::to_string(i));
    }
  }
  
  // The logger should be destroyed here, and the log_rotator_thread should be joined

  ::std::ifstream logFile("test_destructor.log");
  ASSERT_TRUE(logFile.is_open());
  
  ::std::string fileContent((::std::istreambuf_iterator<char>(logFile)),
                            ::std::istreambuf_iterator<char>());
  
  EXPECT_FALSE(fileContent.empty());
  EXPECT_TRUE(fileContent.find("Test message 0") != ::std::string::npos);
  EXPECT_TRUE(fileContent.find("Test message 99") != ::std::string::npos);
  
  logFile.close();
  ::std::remove("test_destructor.log");
}


}  // namespace flow_inspector

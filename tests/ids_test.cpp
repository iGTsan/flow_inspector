
#include <gtest/gtest.h>
#include "ids.h"
#include "pcap_reader.h"
#include <fstream>


namespace flow_inspector::internal {


TEST(IDSTest, SingleThreadInit) {
  auto reader = ::std::make_unique<PcapReader>();
  IDS ids{1, ::std::move(reader)};
}


TEST(IDSTest, MultiThreadInit) {
  auto reader = ::std::make_unique<PcapReader>();
  IDS ids{4, ::std::move(reader)};
}


TEST(IDSTest, DestructorExportsLogsToSpecifiedOutputFile) {
  const ::std::string testOutputFilename = "test_output.log";
  const ::std::string expectedLogMessage = "IDS stopped.";
  
  {
    auto reader = ::std::make_unique<PcapReader>();
    IDS ids{1, ::std::move(reader)};
    ids.setOutputFilename(testOutputFilename);
  }
  
  ::std::ifstream logFile(testOutputFilename);
  ASSERT_TRUE(logFile.is_open());
  
  ::std::string logContent((::std::istreambuf_iterator<char>(logFile)),
      ::std::istreambuf_iterator<char>());
  
  EXPECT_NE(logContent.find(expectedLogMessage), ::std::string::npos);
  
  logFile.close();
  ::std::remove(testOutputFilename.c_str());
}


TEST(IDSTest, ProcessLargeNumberOfPackets) {
  const ::std::string testOutputFilename = "test_output2.log";
  
  {
    auto reader = ::std::make_unique<PcapReader>();
    reader->setFilename("http.pcap");
    IDS ids{4, ::std::move(reader)};
    ids.setOutputFilename(testOutputFilename);
    ids.setLogLevel(Logger::LogLevel::DEBUG);
    ids.start();
  }
  
  ::std::ifstream log_file(testOutputFilename);
  ASSERT_TRUE(log_file.is_open());
  ::std::string log_str;

  EXPECT_TRUE(::std::getline(log_file, log_str));
  EXPECT_TRUE(log_str.find("Message: IDS stopped.") != ::std::string::npos);
  
  log_file.close();
}


TEST(IDSTest, ProcessPacketsWithAlert) {
  const ::std::string testOutputFilename = "test_output3.log";
  
  {
    auto reader = ::std::make_unique<PcapReader>();
    reader->setFilename("double_packets.pcap");
    IDS ids{4, ::std::move(reader)};
    ids.setOutputFilename(testOutputFilename);
    ids.loadRules("double_packets_one_hit.rule");
    ids.start();
  }
  
  ::std::ifstream log_file(testOutputFilename);
  ASSERT_TRUE(log_file.is_open());
  ::std::string log_str;

  for (int i = 0; i < 1; i++) {
    EXPECT_TRUE(::std::getline(log_file, log_str));
    EXPECT_TRUE(log_str.find("double_packets_one_hit")
        != ::std::string::npos);
  }
  EXPECT_TRUE(::std::getline(log_file, log_str));
  EXPECT_TRUE(log_str.find("Message: IDS stopped.") != ::std::string::npos);
  
  log_file.close();
}


}  // namespace flow_inspector::internal

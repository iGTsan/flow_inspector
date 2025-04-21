
#include <gtest/gtest.h>
#include "ids.h"
#include "logger.h"
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
    ids.setLogLevel(Logger::LogLevel::INFO);
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
  EXPECT_TRUE(log_str.find("Message: IDS stopped.") != ::std::string::npos) << log_str;
  
  log_file.close();
}


timeval convertTimespecToTimeval(const timespec& ts) {
  timeval tv;
  tv.tv_sec = ts.tv_sec;
  tv.tv_usec = ts.tv_nsec / 1000;
  return tv;
}


bool comparePcapFiles(const ::std::string& file1, const ::std::string& file2) {
  auto readPackets = [](const ::std::string& filename) {
    flow_inspector::PcapReader reader;
    reader.setFilename(filename);

    ::std::vector<::std::pair<timeval, ::std::vector<u_char>>> packets;

    reader.setProcessor([&packets](const internal::Packet& packet) {
      timeval ts = convertTimespecToTimeval(packet.packet.getPacketTimeStamp());
      const u_char* data = packet.packet.getRawData();
      size_t len = packet.packet.getRawDataLen();
      packets.emplace_back(ts, ::std::vector<u_char>(data, data + len));
    });

    reader.startReading();
    return packets;
  };

  auto packets1 = readPackets(file1);
  auto packets2 = readPackets(file2);

  if (packets1.size() != packets2.size()) {
    return false;
  }

  auto packetComparator = [](const auto& p1, const auto& p2) {
    if (p1.first.tv_sec != p2.first.tv_sec) return p1.first.tv_sec < p2.first.tv_sec;
    if (p1.first.tv_usec != p2.first.tv_usec) return p1.first.tv_usec < p2.first.tv_usec;
    return p1.second < p2.second;
  };

  ::std::sort(packets1.begin(), packets1.end(), packetComparator);
  ::std::sort(packets2.begin(), packets2.end(), packetComparator);

  for (size_t i = 0; i < packets1.size(); ++i) {
    EXPECT_EQ(packets1[i].first.tv_sec, packets2[i].first.tv_sec)
        << "Different seconds at packet " << i;
    EXPECT_EQ(packets1[i].first.tv_usec, packets2[i].first.tv_usec)
        << "Different microseconds at packet " << i;
    EXPECT_EQ(packets1[i].second, packets2[i].second)
        << "Different data at packet " << i;
  }
  return true;
}


TEST(IDSTest, ALotOfPacketsWithSaving) {
  const ::std::string testOutputFilename = "test_output4.log";
  const ::std::string testPcapOutputFilename = "test_output4.pcap";
  
  {
    auto reader = ::std::make_unique<PcapReader>();
    reader->setFilename("a_lot_of.pcap");
    IDS ids{4, ::std::move(reader)};
    ids.setOutputFilename(testOutputFilename);
    ids.setPcapOutputFilename(testPcapOutputFilename);
    ids.setLogLevel(Logger::LogLevel::INFO);
    ids.loadRules("pcap_all.rule");
    ids.start();
  }

  EXPECT_TRUE(comparePcapFiles("a_lot_of.pcap", testPcapOutputFilename));
}


}  // namespace flow_inspector::internal

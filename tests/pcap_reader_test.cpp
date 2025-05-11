#include <gtest/gtest.h>

#include "pcap_reader.h"


namespace flow_inspector {


TEST(PcapReaderTest, ShouldSuccessfullySetPacketProcessor) {
  PcapReader reader;
  bool processorCalled = false;

  PcapReader::PacketProcessor testProcessor = [&processorCalled](
      const internal::Packet& packet) {
    processorCalled = true;
  };

  reader.setProcessor(testProcessor);

  std::string testPcapFile = "single_packet.pcap";
  reader.setFilename(testPcapFile);
  reader.startReading();

  EXPECT_TRUE(processorCalled);
}


TEST(PcapReaderTest, ReadEmptyPcap) {
  PcapReader reader;
  bool processorCalled = false;

  PcapReader::PacketProcessor testProcessor = [&processorCalled](
      const internal::Packet& packet) {
    processorCalled = true;
  };

  reader.setProcessor(testProcessor);

  std::string testPcapFile = "empty.pcap";
  reader.setFilename(testPcapFile);
  reader.startReading();

  EXPECT_FALSE(processorCalled);
}


TEST(PcapReaderTest, ReadSinglePacket) {
  PcapReader reader;
  ::std::vector<internal::Packet> capturedPackets;

  PcapReader::PacketProcessor testProcessor = [&capturedPackets](
      const internal::Packet& packet) {
    capturedPackets.push_back(packet.copy());
  };

  reader.setProcessor(testProcessor);

  ::std::string testPcapFile = "single_packet.pcap";
  reader.setFilename(testPcapFile);
  reader.startReading();

  EXPECT_FALSE(capturedPackets.empty());

  EXPECT_EQ(capturedPackets[0].toString(),
      "[8 0 0 0 0 0 0 1 3 4 0 6 0 0 0 0 0 0 0 0 69 0 0 40 0 0 64 0 64 6 60 206 127 0 0 1 127 0 0 "
      "1 52 66 189 146 0 0 0 0 169 10 104 195 80 20 0 0 174 43 0 0]");
}


TEST(PcapReaderTest, ReadDoublePackets) {
  PcapReader reader;
  ::std::vector<internal::Packet> capturedPackets;

  PcapReader::PacketProcessor testProcessor = [&capturedPackets](
      const internal::Packet& packet) {
    capturedPackets.push_back(packet.copy());
  };

  reader.setProcessor(testProcessor);

  ::std::string testPcapFile = "double_packets.pcap";
  reader.setFilename(testPcapFile);
  reader.startReading();

  EXPECT_EQ(capturedPackets.size(), 2);

  EXPECT_EQ(capturedPackets[0].toString(),
      "[8 0 0 0 0 0 0 1 3 4 0 6 0 0 0 0 0 0 0 0 69 0 0 60 152 151 64 0 64 6 164 34 127 0 0 1 127 "
      "0 0 1 140 186 52 66 20 28 45 199 0 0 0 0 160 2 255 215 254 48 0 0 2 4 255 215 4 2 8 10 226"
      " 115 227 101 0 0 0 0 1 3 3 7]");
  EXPECT_EQ(capturedPackets[1].toString(),
      "[8 0 0 0 0 0 0 1 3 4 0 6 0 0 0 0 0 0 0 0 69 0 0 40 0 0 64 0 64 6 60 206 127 0 0 1 127 0 0 "
      "1 52 66 140 186 0 0 0 0 20 28 45 200 80 20 0 0 174 237 0 0]");
}


}  // namespace flow_inspector

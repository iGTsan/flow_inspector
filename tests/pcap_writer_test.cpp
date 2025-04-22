#include <gtest/gtest.h>
#include "pcap_writer.h"
#include "pcap_reader.h"

#include "RawPacket.h"


namespace flow_inspector {


TEST(PcapWriterTest, SavePacket) {
  internal::Packet testPacket{internal::rawPacketFromVector(::std::vector<internal::byte>(10, 0xAA))};
  {
    PcapWriter writer{::pcpp::LinkLayerType::LINKTYPE_ETHERNET};
    writer.setOutputFilename("test_output.pcap");

    writer.savePacket(testPacket);
  }

  // Open the generated pcap file and verify its contents
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_offline("test_output.pcap", errbuf);
  ASSERT_NE(handle, nullptr) << "Failed to open test_output.pcap: " << errbuf;

  struct pcap_pkthdr* header;
  const u_char* packet;
  int result = pcap_next_ex(handle, &header, &packet);
  ASSERT_EQ(result, 1) << "Failed to read packet from pcap file";

  EXPECT_EQ(memcmp(packet, testPacket.packet->getRawData(), testPacket.packet->getRawDataLen()), 0);

  pcap_close(handle);
  std::remove("test_output.pcap");
}


TEST(PcapWriterReaderTest, SaveAndReadPacket) {
  internal::Packet testPacket{internal::rawPacketFromVector(::std::vector<internal::byte>{
      0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // Ethernet destination
      0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, // Ethernet source
      0x08, 0x00,                         // IP protocol type
      0x45, 0x00, 0x00, 0x1C,             // IP header (version, length)
      0x00, 0x00, 0x40, 0x00, 0x40, 0x11, // More IP header fields
      0xA6, 0xEC,                         // Header checksum
      192, 168, 1, 1,                     // Source IP
      192, 168, 1, 2                      // Destination IP
  })};

  {
    PcapWriter writer{::pcpp::LinkLayerType::LINKTYPE_ETHERNET};
    writer.setOutputFilename("test_output.pcap");
    writer.savePacket(testPacket);
  }

  PcapReader reader;
  ::std::vector<internal::Packet> capturedPackets;

  PcapReader::PacketProcessor processor = [&capturedPackets](const internal::Packet& packet) {
    capturedPackets.push_back(packet.copy());
  };

  reader.setProcessor(processor);
  reader.setFilename("test_output.pcap");
  reader.startReading();

  ASSERT_EQ(capturedPackets.size(), 1);

  const auto& readPacket = capturedPackets[0];
  EXPECT_EQ(readPacket, testPacket);

  ::std::remove("test_output.pcap");
}


}  // namespace flow_inspector

#include <gtest/gtest.h>
#include "pcap_writer.h"


namespace flow_inspector {


TEST(PcapWriterTest, SavePacket) {
  internal::Packet testPacket{::std::vector<internal::byte>(10, 0xAA)};
  {
    PcapWriter writer;
    writer.setOutputFilename("test_output.pcap");

    testPacket.header.ts.tv_sec = 1234567890;
    testPacket.header.ts.tv_usec = 123456;
    testPacket.header.caplen = 10;
    testPacket.header.len = 10;

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

  EXPECT_EQ(header->ts.tv_sec, testPacket.header.ts.tv_sec);
  EXPECT_EQ(header->ts.tv_usec, testPacket.header.ts.tv_usec);
  EXPECT_EQ(header->caplen, testPacket.header.caplen);
  EXPECT_EQ(header->len, testPacket.header.len);
  EXPECT_EQ(memcmp(packet, testPacket.bytes->data(), testPacket.header.caplen), 0);

  pcap_close(handle);
  std::remove("test_output.pcap");
}



}  // namespace flow_inspector

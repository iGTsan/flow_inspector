#include <gtest/gtest.h>
#include "packet_processors_pool.h"
#include "pcap_reader.h"


namespace flow_inspector::internal {


TEST(PacketProcessorsPoolTest, SingleThreadInit) {
  Logger logger;
  EventsHandler handler{logger};
  Analyzer analyzer{logger, handler};
  PacketProcessorsPool pool{analyzer, 1};
}


TEST(PacketProcessorsPoolTest, MultiThreadInit) {
  Logger logger;
  EventsHandler handler{logger};
  Analyzer analyzer{logger, handler};
  PacketProcessorsPool pool{analyzer, 4};
}


TEST(PacketProcessorsPoolTest, AddPacketToQueue) {
  Logger logger;
  EventsHandler handler{logger};
  Analyzer analyzer{logger, handler};
  const internal::Packet test_packet{{1, 2, 3, 4}};
  size_t cnt = 0;

  {
    PacketProcessorsPool pool{analyzer, 1};
    auto callback = [&](auto& packet) {
      EXPECT_EQ(packet, test_packet);
      cnt++;
    };
    pool.addCallback(callback);

    pool.addPacket(test_packet);
  }

  EXPECT_EQ(cnt, 1);
}


TEST(PacketProcessorsPoolTest, ProcessLargeNumberPacket) {
  Logger logger;
  EventsHandler handler{logger};
  Analyzer analyzer{logger, handler};

  size_t cnt = 0;

  {
    PacketProcessorsPool pool{analyzer, 1};
    auto callback = [&](auto& packet) {
      cnt++;
    };
    pool.addCallback(callback);

    PcapReader reader;
    reader.setProcessor([&](const internal::Packet& packet) {
      pool.addPacket(packet);
    });
    reader.startReading("http.pcap");
  }

  EXPECT_EQ(cnt, 220);
}


}  // namespace flow_inspector::internal

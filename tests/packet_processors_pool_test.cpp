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
  internal::Packet test_packet{internal::rawPacketFromVector({1, 2, 3, 4})};
  size_t cnt = 0;

  {
    PacketProcessorsPool pool{analyzer, 1};
    auto callback = [&](auto& packet) {
      EXPECT_EQ(packet, test_packet);
      cnt++;
    };
    pool.addCallback(callback);

    pool.addPacket(test_packet.copy());
  }

  EXPECT_EQ(cnt, 1);
}


TEST(PacketProcessorsPoolTest, ProcessLargeNumberOfPacketSingleThread) {
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
      pool.addPacket(packet.copy());
    });
    reader.setFilename("http.pcap");
    reader.startReading();
  }

  EXPECT_EQ(cnt, 220);
}


TEST(PacketProcessorsPoolTest, ProcessLargeNumberOfPacketMultiThread) {
  Logger logger;
  EventsHandler handler{logger};
  Analyzer analyzer{logger, handler};

  ::std::atomic<size_t> cnt{0};

  {
    PacketProcessorsPool pool{analyzer, 4};
    auto callback = [&](auto& packet) {
      cnt.fetch_add(1);
    };
    pool.addCallback(callback);

    PcapReader reader;
    reader.setProcessor([&](const internal::Packet& packet) {
      pool.addPacket(packet.copy());
    });
    reader.setFilename("http.pcap");
    reader.startReading();
  }

  EXPECT_EQ(cnt.load(), 220);
}


}  // namespace flow_inspector::internal

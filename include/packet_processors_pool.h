#pragma once

#include <atomic>
#include <thread>

#include "analyzer.h"
#include "concurrentqueue.h"


namespace flow_inspector {


class PacketProcessorsPool {
 public:
  using Callback = ::std::function<void(const internal::Packet&)>;

  PacketProcessorsPool(Analyzer& analyzer, const uint8_t num_packet_processors) noexcept;

  void addCallback(Callback callback) noexcept;

  void addPacket(internal::Packet packet) noexcept;

  bool getPacket(internal::Packet& result) noexcept;

  ~PacketProcessorsPool() noexcept;

  void finish() noexcept;

 private:
  static constexpr ::std::chrono::milliseconds kSleepTime{10};

  void processPacket() noexcept;

  ::moodycamel::ConcurrentQueue<internal::Packet> packets_;

  ::std::vector<::std::thread> processors_;
  ::std::vector<Callback> callbacks_;

  Analyzer& analyzer_;
  ::std::atomic<bool> done_{false};
};


}  // namespace flow_inspector

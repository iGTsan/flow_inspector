#include <atomic>
#include <thread>

#include "analyzer.h"
#include "concurrentqueue.h"
#include "debug_logger.h"
#include "packet_processors_pool.h"


namespace flow_inspector {


PacketProcessorsPool::PacketProcessorsPool(
    Analyzer& analyzer, const uint8_t num_packet_processors) noexcept
  : analyzer_{analyzer}
{
  addCallback([this](const internal::Packet& packet) {
    analyzer_.detectThreats(packet);
  });
  for (uint8_t i = 0; i < num_packet_processors; ++i) {
    internal::coutDebug() << "thread initialization started" << std::endl;
    processors_.emplace_back(&PacketProcessorsPool::processPacket, this);
    internal::coutDebug() << "thread initialized" << std::endl;
  }
}

void PacketProcessorsPool::addCallback(Callback callback) noexcept {
  callbacks_.push_back(callback);
}

void PacketProcessorsPool::addPacket(internal::Packet packet) noexcept {
  packets_.enqueue(::std::move(packet));
}

bool PacketProcessorsPool::getPacket(internal::Packet& result) noexcept {
  while (!packets_.try_dequeue(result)) {
    if (done_.load()) {
      return false;
    }
    ::std::this_thread::sleep_for(kSleepTime);
  }
  return true;
}

PacketProcessorsPool::~PacketProcessorsPool() noexcept {
  finish();
}

void PacketProcessorsPool::finish() noexcept {
  if (done_.load()) {
    return;
  }
  internal::coutDebug() << "finish called" << std::endl;
  done_.store(true);
  internal::coutDebug() << "done stored" << std::endl;
  for (auto& thread : processors_) {
    thread.join();
  }
}

void PacketProcessorsPool::processPacket() noexcept {
  internal::coutDebug() << "thread started" << std::endl;
  internal::Packet packet{};
  while (getPacket(packet)) {
    packet.parse();
    for (const auto& callback : callbacks_) {
      callback(packet);
    }
  }
  internal::coutDebug() << "thread ended" << std::endl;
}


}  // namespace flow_inspector

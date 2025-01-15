#pragma once

#include <atomic>
#include <thread>

#include "analyzer.h"
#include "concurrentqueue.h"


namespace flow_inspector {


class PacketProcessorsPool {
public:
  using Callback = ::std::function<void(const internal::Packet&)>;

  PacketProcessorsPool(Analyzer& analyzer, const uint8_t num_packet_processors) noexcept
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

  void addCallback(Callback callback) noexcept {
    callbacks_.push_back(callback);
  }

  void addPacket(internal::Packet packet) noexcept {
    packets_.enqueue(::std::move(packet));
  }

  bool getPacket(internal::Packet& result) noexcept {
    while (!packets_.try_dequeue(result)) {
      if (done_.load()) {
        return false;
      }
      ::std::this_thread::sleep_for(kSleepTime);
    }
    return true;
  }

  ~PacketProcessorsPool() noexcept {
    finish();
  }

  void finish() noexcept {
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

private:
  static constexpr ::std::chrono::milliseconds kSleepTime{10};

  void processPacket() noexcept {
    internal::coutDebug() << "thread started" << std::endl;
    internal::Packet packet{{}};
    while (getPacket(packet)) {
      for (const auto& callback : callbacks_) {
        callback(packet);
      }
    }
    internal::coutDebug() << "thread ended" << std::endl;
  }

  ::moodycamel::ConcurrentQueue<internal::Packet> packets_;

  ::std::vector<::std::thread> processors_;
  ::std::vector<Callback> callbacks_;

  Analyzer& analyzer_;
  ::std::atomic<bool> done_{false};
};


}  // namespace flow_inspector

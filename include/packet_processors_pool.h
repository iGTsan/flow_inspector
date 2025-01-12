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
      std::cout << "thread initialization started" << std::endl;
      processors_.emplace_back(&PacketProcessorsPool::processPacket, this);
      std::cout << "thread initialized" << std::endl;
    }
  }

  void addCallback(Callback callback) noexcept {
    callbacks_.push_back(callback);
  }

  void addPacket(internal::Packet packet) noexcept {
    std::cout << "packet added" << std::endl;
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
    std::cout << "finish called" << std::endl;
    done_.store(true);
    std::cout << "done stored" << std::endl;
    for (auto& thread : processors_) {
      thread.join();
    }
  }

private:
  static constexpr ::std::chrono::milliseconds kSleepTime{10};

  void processPacket() noexcept {
    std::cout << "thread started" << std::endl;
    internal::Packet packet{{}};
    while (getPacket(packet)) {
      for (const auto& callback : callbacks_) {
        callback(packet);
      }
    }
    std::cout << "thread ended" << std::endl;
  }

  ::moodycamel::ConcurrentQueue<internal::Packet> packets_;

  ::std::vector<::std::thread> processors_;
  ::std::vector<Callback> callbacks_;

  Analyzer& analyzer_;
  ::std::atomic<bool> done_{false};
};


}  // namespace flow_inspector

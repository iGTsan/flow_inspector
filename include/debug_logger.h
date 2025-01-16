#pragma once

#include <iostream>
#include <streambuf>
#include <ostream>


namespace flow_inspector::internal {


class NullBuffer : public ::std::streambuf {
protected:
    virtual int overflow(int c) override {
        return c;
    }
};

class NullOStream : public ::std::ostream {
public:
  NullOStream() : ::std::ostream(&nullBuffer) {}

private:
  NullBuffer nullBuffer;
};


class CoutLevel {
public:
  enum class Level {
    INFO,
    DEBUG,
  };

  ::std::ostream& getStream(CoutLevel::Level level) noexcept {
    if (level <= level_) {
      return ::std::cout;
    }
    return null_ostream;
  }

  void enable() noexcept {
    level_ = Level::DEBUG;
  }

  void disable() noexcept {
    level_ = Level::INFO;
  }

private:
  NullOStream null_ostream;
  Level level_{Level::INFO};
};

inline CoutLevel& getCoutLevel() {
  static CoutLevel cout_level;
  return cout_level;
}

inline ::std::ostream& coutDebug() {
  auto& cout_level = getCoutLevel();
  return cout_level.getStream(CoutLevel::Level::DEBUG);
}

inline ::std::ostream& coutInfo() {
  auto& cout_level = getCoutLevel();
  return cout_level.getStream(CoutLevel::Level::INFO);
}

}  // namespace flow_inspector::internal

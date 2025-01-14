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


class CoutDebug {
public:
  ::std::ostream& getStream() noexcept {
    if (debug_enabled_) {
      return ::std::cout;
    }
    return null_ostream;
  }

  void enable() noexcept {
    debug_enabled_ = true;
  }

  void disable() noexcept {
    debug_enabled_ = false;
  }

private:
  bool debug_enabled_{false};
  NullOStream null_ostream;
};

inline CoutDebug& getCoutDebug() {
  static CoutDebug cout_debug;
  return cout_debug;
}

inline ::std::ostream& coutDebug() {
  auto& cout_debug = getCoutDebug();
  return cout_debug.getStream();
}

}  // namespace flow_inspector::internal

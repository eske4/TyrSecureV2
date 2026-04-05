#include "EPollManager.hpp"
#include <catch2/catch_test_macros.hpp>
#include <functional>
#include <sys/eventfd.h>
#include <unistd.h>

namespace sys = OdinSight::System;

// Bridge class to use lambdas with the IEPollListener interface
class TestListener : public sys::IEPollListener {
public:
  TestListener(const sys::FD& fd, uint32_t events, std::function<void(uint32_t)> cb)
      : m_fd(fd), m_events(events), m_cb(std::move(cb)) {}

  const sys::FD& getFd() const override { return m_fd; }
  uint32_t       getEvents() const override { return m_events; }
  void           onEpollEvent(uint32_t events) override { m_cb(events); }

private:
  const sys::FD&                m_fd;
  uint32_t                      m_events;
  std::function<void(uint32_t)> m_cb;
};

// -----------------------------------------------------------------------------
// Fixed Tests
// -----------------------------------------------------------------------------

TEST_CASE("[EPoll] - Manual Unsubscribe Logic", "[epoll]") {
  auto manager = sys::EPollManager::create().value();

  // Use a raw eventfd for the test scope
  int  raw_fd     = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  auto test_fd    = sys::FD::adopt(raw_fd).value();
  int  call_count = 0;

  auto listener = std::make_unique<TestListener>(test_fd, EPOLLIN, [&](uint32_t) {
    uint64_t val;
    (void) read(test_fd.get(), &val, sizeof(val));
    call_count++;
  });

  // 1. Subscribe
  REQUIRE(manager->subscribe(std::move(listener)).has_value());

  // 2. Unsubscribe immediately
  REQUIRE(manager->unsubscribe(test_fd.get()).has_value());

  // 3. Signal the FD
  uint64_t val = 1;
  write(test_fd.get(), &val, sizeof(val));

  // 4. Poll. Because it's in m_pending_removal, process_event MUST skip it.
  auto res = manager->poll(0);
  REQUIRE(res.has_value());

  // 5. Verify
  CHECK(call_count == 0);
}

TEST_CASE("[EPoll] - Mid-loop Deletion Determinism", "[epoll]") {
  auto manager = sys::EPollManager::create().value();

  int  raw_a = eventfd(0, EFD_NONBLOCK);
  int  raw_b = eventfd(0, EFD_NONBLOCK);
  auto fdA   = sys::FD::adopt(raw_a).value();
  auto fdB   = sys::FD::adopt(raw_b).value();

  bool b_called            = false;
  bool unsubscribe_success = false;

  // A unregisters B
  auto listenerA = std::make_unique<TestListener>(fdA, EPOLLIN, [&](uint32_t) {
    uint64_t val;
    (void) read(fdA.get(), &val, sizeof(val));
    auto res            = manager->unsubscribe(fdB.get());
    unsubscribe_success = res.has_value();
  });

  auto listenerB = std::make_unique<TestListener>(fdB, EPOLLIN, [&](uint32_t) {
    uint64_t val;
    (void) read(fdB.get(), &val, sizeof(val));
    b_called = true;
  });

  REQUIRE(manager->subscribe(std::move(listenerA)));
  REQUIRE(manager->subscribe(std::move(listenerB)));

  // STAGE 1: Signal A and Poll.
  // This moves B into 'm_pending_removal'.
  uint64_t signal_count = 1;
  write(fdA.get(), &signal_count, sizeof(signal_count));
  REQUIRE(manager->poll(0).has_value());

  // STAGE 2: Signal B and Poll.
  // Manager should skip B because it's in the removal list.
  write(fdB.get(), &signal_count, sizeof(signal_count));
  REQUIRE(manager->poll(0).has_value());

  CHECK_FALSE(b_called);
}

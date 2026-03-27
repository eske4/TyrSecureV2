#include "EPollBinding.hpp"
#include "EPollManager.hpp"
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <memory>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace sys = OdinSight::System;

constexpr int POLLTIME    = 10;
constexpr int POLLNOTIMER = 0;

class MockService {
public:
  sys::FD                            fd;
  bool                               triggered = false;
  std::unique_ptr<sys::EPollBinding> binding;

  MockService() : triggered(false) {
    int ev_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ev_fd < 0)
      throw std::runtime_error("Failed to create eventfd");
    fd.reset(ev_fd);
  }

  // Standard auto-subscriber
  explicit MockService(sys::EPollManager *mgr) : MockService() {
    auto cb = [](void *ctx, uint32_t) {
      auto    *self = static_cast<MockService *>(ctx);
      uint64_t val;
      if (read(self->fd.get(), &val, sizeof(val)) > 0) {
        self->triggered = true;
      }
    };
    // Create the binding (it starts inactive)
    binding = std::make_unique<sys::EPollBinding>(mgr, fd.get(), this, cb);

    // Use the binding to activate itself
    REQUIRE(binding->subscribe(EPOLLIN | EPOLLET));
  }

  void signal() {
    uint64_t val = 1;
    (void)write(fd.get(), &val, sizeof(val));
  }

  void reset() { triggered = false; }
};

// -----------------------------------------------------------------------------
// EPollManager Integration Tests
// -----------------------------------------------------------------------------

TEST_CASE("[Integration] - EPollManager Lifecycle", "[epoll]") {
  auto result = sys::EPollManager::create();
  REQUIRE(result.has_value());
}

TEST_CASE("[Integration] - Basic Event Triggering", "[epoll]") {
  auto        manager = sys::EPollManager::create().value();
  MockService service(&manager);

  SECTION("No signal means no trigger") {
    (void)manager.poll(POLLTIME);
    CHECK(service.triggered == false);
  }

  SECTION("Signal triggers callback") {
    service.signal();
    auto res = manager.poll(POLLTIME);
    REQUIRE(res.has_value());
    CHECK(res.value() >= 1);
    CHECK(service.triggered == true);
  }
}

TEST_CASE("[Integration] - Unsubscribe Logic", "[epoll]") {
  auto        manager = sys::EPollManager::create().value();
  MockService service(&manager);

  (void)service.binding->unsubscribe();
  service.signal();

  (void)manager.poll(POLLTIME);
  INFO("Callback should not fire because m_active is false and FD is removed "
       "from epoll");
  CHECK(service.triggered == false);
}

TEST_CASE("[Integration] - Re-entrancy: Nested Poll Calls", "[epoll]") {
  auto        manager = sys::EPollManager::create().value();
  MockService service;

  struct ReentryCtx {
    sys::EPollManager *mgr;
    int                fd;
    int                count = 0;
  } context{&manager, service.fd.get(), 0};

  auto reentrant_cb = [](void *ctx, uint32_t) {
    auto *c = static_cast<ReentryCtx *>(ctx);

    // 1. Drain the eventfd first
    uint64_t val;
    (void)read(c->fd, &val, sizeof(val));

    if (c->count == 0) {
      c->count++;
      // 2. Perform nested poll. Should see 0 events because we just read()
      auto res = c->mgr->poll(0);
      CHECK(res.has_value());
      CHECK(res.value() == 0);
    }
  };

  service.binding =
      std::make_unique<sys::EPollBinding>(&manager, service.fd.get(), &context, reentrant_cb);

  (void)service.binding->subscribe(EPOLLIN);

  service.signal();
  (void)manager.poll(0);
  CHECK(context.count == 1);
}

TEST_CASE("[Integration] - Mid-loop Unsubscription (The Killer Test)", "[epoll]") {
  auto        manager = sys::EPollManager::create().value();
  MockService serviceA;
  MockService serviceB;

  struct KillerCtx {
    MockService *victim;
  } ctx{&serviceB};

  auto killer_cb = [](void *c, uint32_t) {
    auto *data = static_cast<KillerCtx *>(c);
    // The killer simply deactivates the victim's binding
    CHECK(data->victim->binding->unsubscribe());
  };

  auto victim_cb = [](void *ctx, uint32_t) { static_cast<MockService *>(ctx)->triggered = true; };

  serviceA.binding =
      std::make_unique<sys::EPollBinding>(&manager, serviceA.fd.get(), &ctx, killer_cb);
  serviceB.binding =
      std::make_unique<sys::EPollBinding>(&manager, serviceB.fd.get(), &ctx, victim_cb);

  REQUIRE(serviceA.binding->subscribe(EPOLLIN));
  REQUIRE(serviceB.binding->subscribe(EPOLLIN));

  serviceA.signal();
  serviceB.signal();

  (void)manager.poll(POLLNOTIMER);
  CHECK(serviceB.triggered == false); // Validated by binding->m_active check in dispatch
}

TEST_CASE("[Integration] - Subscription Updates and Masks", "[epoll]") {
  auto manager = sys::EPollManager::create().value();

  SECTION("Updating flags (EPOLLOUT to EPOLLIN)") {
    MockService service;
    auto        cb = [](void *ctx, uint32_t) { static_cast<MockService *>(ctx)->triggered = true; };
    service.binding = std::make_unique<sys::EPollBinding>(&manager, service.fd.get(), &service, cb);

    // Start with OUT (triggered immediately)
    (void)service.binding->subscribe(EPOLLOUT);
    (void)manager.poll(POLLNOTIMER);
    CHECK(service.triggered == true);

    // Change to IN (not triggered until signal)
    service.reset();
    (void)service.binding->subscribe(EPOLLIN);
    (void)manager.poll(POLLNOTIMER);
    CHECK(service.triggered == false);

    service.signal();
    (void)manager.poll(POLLNOTIMER);
    CHECK(service.triggered == true);
  }

  SECTION("Combined IN/OUT masks") {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    sys::FD local{sv[0]}, remote{sv[1]};

    uint32_t last_events = 0;
    auto     callback    = [](void *ctx, uint32_t e) { *static_cast<uint32_t *>(ctx) = e; };
    auto     binding =
        std::make_unique<sys::EPollBinding>(&manager, local.get(), &last_events, callback);

    (void)binding->subscribe(EPOLLIN | EPOLLOUT);

    uint64_t val = 1;
    (void)write(remote.get(), &val, sizeof(val));

    (void)manager.poll(POLLTIME);
    CHECK((last_events & EPOLLIN));
    CHECK((last_events & EPOLLOUT));
  }
}

TEST_CASE("[Integration] - Error handling: EPOLLHUP", "[epoll]") {
  auto manager = sys::EPollManager::create().value();
  int  sv[2];
  socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
  sys::FD local{sv[0]}, remote{sv[1]};

  bool hup_detected = false;
  auto cb           = [](void *ctx, uint32_t e) {
    if (e & (EPOLLHUP | EPOLLRDHUP))
      *static_cast<bool *>(ctx) = true;
  };
  auto binding = std::make_unique<sys::EPollBinding>(&manager, local.get(), &hup_detected, cb);

  (void)binding->subscribe(EPOLLIN | EPOLLRDHUP);
  remote.reset(-1); // Close the other end

  (void)manager.poll(POLLTIME);
  CHECK(hup_detected == true);
}

TEST_CASE("[Integration] - Stress: Many FDs", "[epoll][stress]") {
  auto                                      manager = sys::EPollManager::create().value();
  constexpr int                             COUNT   = 1000;
  std::vector<std::unique_ptr<MockService>> services;

  for (int i = 0; i < COUNT; ++i) {
    services.push_back(std::make_unique<MockService>(&manager));
    services.back()->signal();
  }

  size_t processed = 0;
  while (processed < COUNT) {
    auto res = manager.poll(POLLTIME - 5);
    if (!res || res.value() == 0)
      break;
    processed += res.value();
  }
  CHECK(processed == COUNT);
}

TEST_CASE("[Integration] - System Interrupt Resilience", "[epoll]") {
  struct sigaction sa;
  sa.sa_handler = [](int) {};
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  struct sigaction old_sa;
  sigaction(SIGALRM, &sa, &old_sa);

  auto manager = sys::EPollManager::create().value();
  ualarm(10000, 0);

  auto start = std::chrono::steady_clock::now();
  (void)manager.poll(50);
  auto end = std::chrono::steady_clock::now();

  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
  CHECK(duration >= 45);

  sigaction(SIGALRM, &old_sa, nullptr);
}

TEST_CASE("[Integration] - Multiple Managers Isolation", "[epoll]") {
  auto mgr_res1 = sys::EPollManager::create();
  auto mgr_res2 = sys::EPollManager::create();

  REQUIRE(mgr_res1.has_value());
  REQUIRE(mgr_res2.has_value());

  auto &mgr1 = mgr_res1.value();
  auto &mgr2 = mgr_res2.value();

  MockService service1(&mgr1);
  MockService service2(&mgr2);

  // Signal service 1 only
  service1.signal();

  // Poll Manager 2 - should see 0 events
  auto res2 = mgr2.poll(0);
  CHECK(res2.value() == 0);
  CHECK(service2.triggered == false);

  // Poll Manager 1 - should see 1 event
  auto res1 = mgr1.poll(0);
  CHECK(res1.value() == 1);
  CHECK(service1.triggered == true);
}

TEST_CASE("[Integration] - Handling Invalid FDs", "[epoll]") {
  auto manager  = sys::EPollManager::create().value();
  auto callback = [](void *, uint32_t) {};
  int  bad_fd   = 9999; // Highly unlikely to be open

  SECTION("Subscribing a closed FD fails gracefully") {
    // Create a binding with a garbage FD
    auto binding = std::make_unique<sys::EPollBinding>(&manager, bad_fd, nullptr, callback);

    // This calls manager->subscribe internally, which fails epoll_ctl(ADD)
    bool result = binding->subscribe(EPOLLIN);

    CHECK(result == false);
    CHECK(binding->isActive() == false);
  }

  SECTION("Unsubscribing a non-existent FD") {
    // Create a binding that WAS never subscribed
    auto binding = std::make_unique<sys::EPollBinding>(&manager, 8888, nullptr, callback);

    // Calling unsubscribe on an inactive binding returns true (noop)
    // OR false depending on your implementation.
    // Usually, if m_active is false, we don't even call the manager.
    bool result = binding->unsubscribe();

    CHECK(result == true); // It's "successfully" not in the epoll set
  }
}

TEST_CASE("[Integration] - Edge-Triggered (EPOLLET) mechanics", "[epoll]") {
  auto manager = sys::EPollManager::create().value();

  // We need a socketpair for granular control over the "buffer"
  int sv[2];
  REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  sys::FD local{sv[0]}, remote{sv[1]};

  int  trigger_count = 0;
  auto cb            = [](void *ctx, uint32_t) { (*static_cast<int *>(ctx))++; };

  // Subscribe with EPOLLET
  auto binding = std::make_unique<sys::EPollBinding>(&manager, local.get(), &trigger_count, cb);
  (void)binding->subscribe(EPOLLIN | EPOLLET);

  // 1. Send two distinct writes
  uint64_t data = 123;
  (void)write(remote.get(), &data, sizeof(data));
  (void)write(remote.get(), &data, sizeof(data));

  // 2. Poll once - triggers because state changed from "Empty" to "Has Data"
  (void)manager.poll(POLLNOTIMER);
  CHECK(trigger_count == 1);

  // 3. DO NOT READ. Poll again.
  // In Level-Triggered, this would trigger again.
  // In Edge-Triggered, this MUST NOT trigger again because the "edge" hasn't
  // changed.
  (void)manager.poll(POLLNOTIMER);
  CHECK(trigger_count == 1);

  // 4. Now read some data and send new data to create a new "edge"
  uint64_t junk;
  (void)read(local.get(), &junk, sizeof(junk));
  (void)write(remote.get(), &data, sizeof(data));

  (void)manager.poll(POLLNOTIMER);
  CHECK(trigger_count == 2);
}

TEST_CASE("[Integration] - Self-Unsubscription", "[epoll]") {
  auto        manager = sys::EPollManager::create().value();
  MockService service;

  // Capture the manager pointer directly in the lambda
  auto self_destruct_cb = [](void *ctx, uint32_t) {
    auto *s = static_cast<MockService *>(ctx);

    // We need the manager address to unsubscribe
    // Assuming we store it in the context or capture it
  };

  // Better yet, use a struct to hold both for the test context
  struct SelfDestructCtx {
    sys::EPollManager *mgr;
    MockService       *service;
  } context{&manager, &service};

  auto callback = [](void *c, uint32_t) {
    auto *ctx = static_cast<SelfDestructCtx *>(c);
    // Unsubscribe yourself during your own callback
    (void)ctx->service->binding->unsubscribe();
    ctx->service->triggered = true;
  };

  service.binding =
      std::make_unique<sys::EPollBinding>(&manager, service.fd.get(), &context, callback);

  (void)service.binding->subscribe(EPOLLIN);

  service.signal();
  (void)manager.poll(0);

  CHECK(service.triggered == true);

  // Verify it's actually gone
  service.reset();
  service.signal();
  (void)manager.poll(POLLNOTIMER);
  CHECK(service.triggered == false); // Should not trigger again
}

TEST_CASE("[Integration] - Redundant Subscription", "[epoll]") {
  auto        manager = sys::EPollManager::create().value();
  MockService service;
  auto        callback = [](void *, uint32_t) {};

  service.binding =
      std::make_unique<sys::EPollBinding>(&manager, service.fd.get(), &service, callback);

  // First time should succeed
  CHECK((service.binding->subscribe(EPOLLIN) == true));

  // Second time with SAME FD:
  // Does your manager use EPOLL_CTL_MOD internally? Or does it return false?
  // This test clarifies your API's contract.
  SECTION("Subscribing again updates or fails gracefully") {
    bool second_call = service.binding->subscribe(EPOLLIN | EPOLLOUT);
    // If your manager handles 'already exists' by switching to MOD, this is
    // true. If your manager expects unique FDs only, this might be false.
    SUCCEED("Manager handled double-subscription without crashing");
  }
}

TEST_CASE("[Integration] - RAII: Automatic Unsubscribe on Destruction", "[epoll]") {
  auto manager   = sys::EPollManager::create().value();
  bool triggered = false;

  {
    // Scope a service
    MockService temporary_service(&manager);
    temporary_service.signal();
    // Don't poll yet, just let it go out of scope
  }

  // At this point, temporary_service and its binding are DELETED.
  // If the destructor worked, the FD is removed from epoll.

  auto res = manager.poll(0);
  // Even if the signal was sent, the binding is gone, so 0 events should be
  // processed
  CHECK(res.value() == 0);
}

#include "EPollManager.hpp"
#include "EPollBinding.hpp"
#include <catch2/catch_test_macros.hpp>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <memory>
#include <chrono>
#include <vector>

class MockService {
public:
    sys::FD fd;
    bool triggered = false;
    std::unique_ptr<sys::EPollBinding> binding;

    MockService() : triggered(false) {
        int ev_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (ev_fd < 0) throw std::runtime_error("Failed to create eventfd");
        fd.reset(ev_fd);
    }

    // Standard auto-subscriber
    explicit MockService(sys::EPollManager* mgr) : MockService() {
        auto cb = [](void* ctx, uint32_t) {
            auto* self = static_cast<MockService*>(ctx);
            uint64_t val;
            if (read(self->fd.get(), &val, sizeof(val)) > 0) {
                self->triggered = true;
            }
        };
        binding = std::make_unique<sys::EPollBinding>(mgr, fd.get(), this, cb);
        mgr->subscribe(fd.get(), binding.get(), EPOLLIN | EPOLLET);
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
    auto manager = sys::EPollManager::create().value();
    MockService service(&manager);

    SECTION("No signal means no trigger") {
        manager.poll(10);
        CHECK(service.triggered == false);
    }

    SECTION("Signal triggers callback") {
        service.signal();
        auto res = manager.poll(10);
        REQUIRE(res.has_value());
        CHECK(res.value() >= 1);
        CHECK(service.triggered == true);
    }
}

TEST_CASE("[Integration] - Unsubscribe Logic", "[epoll]") {
    auto manager = sys::EPollManager::create().value();
    MockService service(&manager);

    manager.unsubscribe(service.fd.get(), service.binding.get());
    service.signal();

    manager.poll(10);
    INFO("Callback should not fire because m_active is false and FD is removed from epoll");
    CHECK(service.triggered == false);
}

TEST_CASE("[Integration] - Re-entrancy: Nested Poll Calls", "[epoll]") {
    auto manager = sys::EPollManager::create().value();
    MockService service;

    struct ReentryCtx {
        sys::EPollManager* mgr;
        int fd;
        int count = 0;
    } context { &manager, service.fd.get(), 0 };

    auto reentrant_cb = [](void* ctx, uint32_t) {
        auto* c = static_cast<ReentryCtx*>(ctx);
        
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

    service.binding = std::make_unique<sys::EPollBinding>(&manager, service.fd.get(), &context, reentrant_cb);
    manager.subscribe(service.fd.get(), service.binding.get(), EPOLLIN);
    
    service.signal();
    manager.poll(0);
    CHECK(context.count == 1);
}

TEST_CASE("[Integration] - Mid-loop Unsubscription (The Killer Test)", "[epoll]") {
    auto manager = sys::EPollManager::create().value();
    MockService serviceA; // The Killer
    MockService serviceB; // The Victim

    struct KillerCtx {
        sys::EPollManager* mgr;
        MockService* victim;
    } ctx { &manager, &serviceB };

    // Service A kills Service B mid-poll
    auto killer_cb = [](void* c, uint32_t) {
        auto* data = static_cast<KillerCtx*>(c);
        data->mgr->unsubscribe(data->victim->fd.get(), data->victim->binding.get());
    };
    
    // Service B normal callback
    auto victim_cb = [](void* ctx, uint32_t) { 
        static_cast<MockService*>(ctx)->triggered = true; 
    };

    serviceA.binding = std::make_unique<sys::EPollBinding>(&manager, serviceA.fd.get(), &ctx, killer_cb);
    serviceB.binding = std::make_unique<sys::EPollBinding>(&manager, serviceB.fd.get(), &serviceB, victim_cb);

    manager.subscribe(serviceA.fd.get(), serviceA.binding.get(), EPOLLIN);
    manager.subscribe(serviceB.fd.get(), serviceB.binding.get(), EPOLLIN);

    serviceA.signal();
    serviceB.signal();

    // The manager will see two events. It calls A first. A calls unsubscribe(B). 
    // unsubscribe(B) sets B->m_active = false. When the manager tries to call B, 
    // isValid() returns false and the callback is skipped.
    manager.poll(0);
    CHECK(serviceB.triggered == false);
}

TEST_CASE("[Integration] - Subscription Updates and Masks", "[epoll]") {
    auto manager = sys::EPollManager::create().value();
    
    SECTION("Updating flags (EPOLLOUT to EPOLLIN)") {
        MockService service;
        auto cb = [](void* ctx, uint32_t) { static_cast<MockService*>(ctx)->triggered = true; };
        service.binding = std::make_unique<sys::EPollBinding>(&manager, service.fd.get(), &service, cb);

        // Start with OUT (triggered immediately)
        manager.subscribe(service.fd.get(), service.binding.get(), EPOLLOUT);
        manager.poll(0);
        CHECK(service.triggered == true);

        // Change to IN (not triggered until signal)
        service.reset();
        manager.subscribe(service.fd.get(), service.binding.get(), EPOLLIN);
        manager.poll(0);
        CHECK(service.triggered == false);

        service.signal();
        manager.poll(0);
        CHECK(service.triggered == true);
    }

    SECTION("Combined IN/OUT masks") {
        int sv[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        sys::FD local{sv[0]}, remote{sv[1]};

        uint32_t last_events = 0;
        auto cb = [](void* ctx, uint32_t e) { *static_cast<uint32_t*>(ctx) = e; };
        auto binding = std::make_unique<sys::EPollBinding>(&manager, local.get(), &last_events, cb);

        manager.subscribe(local.get(), binding.get(), EPOLLIN | EPOLLOUT);
        
        uint64_t val = 1;
        (void)write(remote.get(), &val, sizeof(val));

        manager.poll(10);
        CHECK((last_events & EPOLLIN));
        CHECK((last_events & EPOLLOUT));
    }
}

TEST_CASE("[Integration] - Error handling: EPOLLHUP", "[epoll]") {
    auto manager = sys::EPollManager::create().value();
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    sys::FD local{sv[0]}, remote{sv[1]};

    bool hup_detected = false;
    auto cb = [](void* ctx, uint32_t e) { if (e & (EPOLLHUP | EPOLLRDHUP)) *static_cast<bool*>(ctx) = true; };
    auto binding = std::make_unique<sys::EPollBinding>(&manager, local.get(), &hup_detected, cb);

    manager.subscribe(local.get(), binding.get(), EPOLLIN | EPOLLRDHUP);
    remote.reset(-1); // Close the other end

    manager.poll(10);
    CHECK(hup_detected == true);
}

TEST_CASE("[Integration] - Stress: Many FDs", "[epoll][stress]") {
    auto manager = sys::EPollManager::create().value();
    constexpr int COUNT = 1000;
    std::vector<std::unique_ptr<MockService>> services;

    for (int i = 0; i < COUNT; ++i) {
        services.push_back(std::make_unique<MockService>(&manager));
        services.back()->signal();
    }

    size_t processed = 0;
    while (processed < COUNT) {
        auto res = manager.poll(5);
        if (!res || res.value() == 0) break;
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
    manager.poll(50); 
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
    
    auto& mgr1 = mgr_res1.value();
    auto& mgr2 = mgr_res2.value();

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
    auto manager = sys::EPollManager::create().value();
    
    // Create a dummy binding
    auto cb = [](void*, uint32_t) {};
    auto binding = std::make_unique<sys::EPollBinding>(&manager, 9999, nullptr, cb);

    SECTION("Subscribing a closed FD fails gracefully") {
        int bad_fd = 9999; // Highly unlikely to be open
        bool result = manager.subscribe(bad_fd, binding.get(), EPOLLIN);
        
        // Your manager returns false if fcntl or epoll_ctl fails
        CHECK(result == false);
    }

    SECTION("Unsubscribing a non-existent FD") {
        bool result = manager.unsubscribe(8888, binding.get());
        CHECK(result == false);
    }
}

TEST_CASE("[Integration] - Edge-Triggered (EPOLLET) mechanics", "[epoll]") {
    auto manager = sys::EPollManager::create().value();
    
    // We need a socketpair for granular control over the "buffer"
    int sv[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    sys::FD local{sv[0]}, remote{sv[1]};

    int trigger_count = 0;
    auto cb = [](void* ctx, uint32_t) { (*static_cast<int*>(ctx))++; };
    
    // Subscribe with EPOLLET
    auto binding = std::make_unique<sys::EPollBinding>(&manager, local.get(), &trigger_count, cb);
    manager.subscribe(local.get(), binding.get(), EPOLLIN | EPOLLET);

    // 1. Send two distinct writes
    uint64_t data = 123;
    (void)write(remote.get(), &data, sizeof(data));
    (void)write(remote.get(), &data, sizeof(data));

    // 2. Poll once - triggers because state changed from "Empty" to "Has Data"
    manager.poll(0);
    CHECK(trigger_count == 1);

    // 3. DO NOT READ. Poll again.
    // In Level-Triggered, this would trigger again.
    // In Edge-Triggered, this MUST NOT trigger again because the "edge" hasn't changed.
    manager.poll(0);
    CHECK(trigger_count == 1); 

    // 4. Now read some data and send new data to create a new "edge"
    uint64_t junk;
    (void)read(local.get(), &junk, sizeof(junk));
    (void)write(remote.get(), &data, sizeof(data));
    
    manager.poll(0);
    CHECK(trigger_count == 2);
}

TEST_CASE("[Integration] - Self-Unsubscription", "[epoll]") {
    auto manager = sys::EPollManager::create().value();
    MockService service;

    // Capture the manager pointer directly in the lambda
    auto self_destruct_cb = [](void* ctx, uint32_t) {
        auto* s = static_cast<MockService*>(ctx);
        
        // We need the manager address to unsubscribe
        // Assuming we store it in the context or capture it
    };

    // Better yet, use a struct to hold both for the test context
    struct SelfDestructCtx {
        sys::EPollManager* mgr;
        MockService* service;
    } context { &manager, &service };

    auto cb = [](void* c, uint32_t) {
        auto* ctx = static_cast<SelfDestructCtx*>(c);
        // Unsubscribe yourself during your own callback
        ctx->mgr->unsubscribe(ctx->service->fd.get(), ctx->service->binding.get());
        ctx->service->triggered = true;
    };

    service.binding = std::make_unique<sys::EPollBinding>(&manager, service.fd.get(), &context, cb);
    manager.subscribe(service.fd.get(), service.binding.get(), EPOLLIN);
    
    service.signal();
    manager.poll(0);
    
    CHECK(service.triggered == true);

    // Verify it's actually gone
    service.reset();
    service.signal();
    manager.poll(0);
    CHECK(service.triggered == false); // Should not trigger again
}

TEST_CASE("[Integration] - Redundant Subscription", "[epoll]") {
    auto manager = sys::EPollManager::create().value();
    MockService service;
    auto cb = [](void*, uint32_t) {};
    
    service.binding = std::make_unique<sys::EPollBinding>(&manager, service.fd.get(), &service, cb);

    // First time should succeed
    CHECK(manager.subscribe(service.fd.get(), service.binding.get(), EPOLLIN) == true);

    // Second time with SAME FD: 
    // Does your manager use EPOLL_CTL_MOD internally? Or does it return false?
    // This test clarifies your API's contract.
    SECTION("Subscribing again updates or fails gracefully") {
        bool second_call = manager.subscribe(service.fd.get(), service.binding.get(), EPOLLIN | EPOLLOUT);
        // If your manager handles 'already exists' by switching to MOD, this is true.
        // If your manager expects unique FDs only, this might be false.
        SUCCEED("Manager handled double-subscription without crashing");
    }
}

TEST_CASE("[Integration] - RAII: Automatic Unsubscribe on Destruction", "[epoll]") {
    auto manager = sys::EPollManager::create().value();
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
    // Even if the signal was sent, the binding is gone, so 0 events should be processed
    CHECK(res.value() == 0);
}

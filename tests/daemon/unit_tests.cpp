#include "EPollManager.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sys/eventfd.h>
#include <unistd.h>
#include <signal.h>

constexpr int POLL_TIMEOUT_MS = 10;

class MockService {
public:
    sys::FD fd;
    bool triggered = false;
    EPollBinding binding;

    MockService() {
        fd.reset(eventfd(0, EFD_NONBLOCK));
        binding.context = this;
        binding.on_event = [](void* ctx, uint32_t) {
            auto* self = static_cast<MockService*>(ctx);
            uint64_t val;
            read(self->fd.get(), &val, sizeof(val));
            self->triggered = true;
        };
    }

    void signal() const {
        uint64_t val = 1;
        write(fd.get(), &val, sizeof(val));
    }
};

// ------------------------ EPollManager Tests ------------------------

TEST_CASE("[Integration Test] - EPollManager creation", "[epoll]") {
    auto result = sys::EPollManager::create();
    REQUIRE(result.has_value());
    INFO("EPollManager instance created successfully");
}

TEST_CASE("[Integration Test] - Subscription and basic triggering", "[epoll]") {
    auto result = sys::EPollManager::create();
    REQUIRE(result.has_value());
    auto& manager = result.value();
    MockService service;

    manager.subscribe(service.fd, EPOLLIN, &service.binding);

    INFO("Polling without signal should not trigger callback");
    manager.poll(POLL_TIMEOUT_MS);
    CHECK(service.triggered == false);

    service.signal();
    INFO("Polling after signal should trigger callback");
    auto res = manager.poll(POLL_TIMEOUT_MS);
    REQUIRE(res.has_value());
    CHECK(res.value() == 1);
    CHECK(service.triggered == true);
}

TEST_CASE("[Integration Test] - Unsubscribe stops events", "[epoll]") {
    auto result = sys::EPollManager::create();
    REQUIRE(result.has_value());
    auto& manager = result.value();
    MockService service;

    manager.subscribe(service.fd, EPOLLIN, &service.binding);
    manager.unsubscribe(service.fd, &service.binding);

    service.triggered = false;
    service.signal();

    INFO("Polling should not trigger callback for unsubscribed FD");
    manager.poll(POLL_TIMEOUT_MS);
    CHECK(service.triggered == false);
}

TEST_CASE("[Integration Test] - Mute and Unmute lifecycle", "[epoll]") {
    auto result = sys::EPollManager::create();
    REQUIRE(result.has_value());
    auto& manager = result.value();
    MockService service;

    manager.subscribe(service.fd, EPOLLIN, &service.binding);
    manager.unsubscribe(service.fd, &service.binding);

    INFO("Phase 1: service is muted");
    service.signal();
    manager.poll(POLL_TIMEOUT_MS);
    CHECK(service.triggered == false);

    // Clear events
    uint64_t junk;
    read(service.fd.get(), &junk, sizeof(junk));
    service.triggered = false;

    INFO("Phase 2: service is unmuted (resubscribed)");
    manager.subscribe(service.fd, EPOLLIN, &service.binding);
    service.signal();
    manager.poll(POLL_TIMEOUT_MS);
    CHECK(service.triggered == true);
}

TEST_CASE("[Integration Test] - Multiple services triggered simultaneously", "[epoll]") {
    auto result = sys::EPollManager::create();
    REQUIRE(result.has_value());
    auto& manager = result.value();

    MockService serviceA;
    MockService serviceB;

    manager.subscribe(serviceA.fd, EPOLLIN, &serviceA.binding);
    manager.subscribe(serviceB.fd, EPOLLIN, &serviceB.binding);

    serviceA.signal();
    serviceB.signal();

    INFO("Both services should be triggered in one poll cycle");
    auto res = manager.poll(POLL_TIMEOUT_MS);
    REQUIRE(res.has_value());
    CHECK(res.value() == 2);
    CHECK(serviceA.triggered == true);
    CHECK(serviceB.triggered == true);
}

TEST_CASE("[Integration Test] - Re-entrancy: Poll within callback", "[epoll]") {
    auto result = sys::EPollManager::create();
    REQUIRE(result.has_value());
    auto& manager = result.value();

    MockService serviceA;
    struct ReentryCtx {
        sys::EPollManager* manager;
        MockService* service;
        int count = 0;
    } context { &manager, &serviceA };

    serviceA.binding.on_event = [](void* ctx, uint32_t) {
        auto* c = static_cast<ReentryCtx*>(ctx);
        uint64_t val;
        read(c->service->fd.get(), &val, sizeof(val));

        if (c->count == 0) {
            c->count++;
            INFO("Executing inner re-entrant poll call");
            auto res = c->manager->poll(0);
            CHECK(res.has_value());
            CHECK(res.value() == 0);
        }
    };
    serviceA.binding.context = &context;

    manager.subscribe(serviceA.fd, EPOLLIN, &serviceA.binding);
    serviceA.signal();

    auto res = manager.poll(0);
    REQUIRE(res.has_value());
    CHECK(res.value() == 1);
}

TEST_CASE("[Integration Test] - Stale pointer protections", "[epoll]") {
    auto result = sys::EPollManager::create();
    REQUIRE(result.has_value());
    auto& manager = result.value();

    // Pre-emptive
    MockService service;
    manager.subscribe(service.fd, EPOLLIN, &service.binding);
    service.signal();
    manager.unsubscribe(service.fd, &service.binding);

    service.triggered = false;
    INFO("Polling after unsubscription but before callback execution");
    manager.poll(0);
    CHECK(service.triggered == false);

    // Mid-loop
    MockService serviceA;
    MockService serviceB;
    manager.subscribe(serviceA.fd, EPOLLIN, &serviceA.binding);
    manager.subscribe(serviceB.fd, EPOLLIN, &serviceB.binding);

    struct KillerCtx {
        sys::EPollManager* mgr;
        MockService* killer;
        MockService* victim;
    } ctx { &manager, &serviceA, &serviceB };

    serviceA.binding.on_event = [](void* c, uint32_t) {
        auto* data = static_cast<KillerCtx*>(c);
        INFO("Service A unsubscribes Service B mid-poll");
        data->mgr->unsubscribe(data->victim->fd, &data->victim->binding);
        uint64_t junk;
        read(data->killer->fd.get(), &junk, sizeof(junk));
    };
    serviceA.binding.context = &ctx;

    serviceA.signal();
    serviceB.signal();

    manager.poll(0);
    INFO("Verify Service B was skipped after being unsubscribed mid-loop");
    CHECK(serviceB.triggered == false);
}

TEST_CASE("[Integration Test] - Poll timeout duration", "[epoll]") {
    auto result = sys::EPollManager::create();
    auto& manager = result.value();
    
    auto start = std::chrono::steady_clock::now();
    manager.poll(50); // 50ms timeout
    auto end = std::chrono::steady_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    CHECK(duration >= 50);
}

TEST_CASE("[Integration Test] - EPOLLOUT triggers on writable FD", "[epoll]") {
    auto result = sys::EPollManager::create();
    REQUIRE(result.has_value());
    auto& manager = result.value();

    MockService service;

    // Writable check (eventfd is always writable)
    manager.subscribe(service.fd, EPOLLOUT, &service.binding);

    INFO("Polling should immediately trigger writable callback");
    auto res = manager.poll(POLL_TIMEOUT_MS);
    REQUIRE(res.has_value());
    CHECK(res.value() == 1);
    CHECK(service.triggered == true);
}

#include <sys/socket.h>

TEST_CASE("[Integration Test] - EPOLLERR on closed socket", "[epoll]") {
    auto result = sys::EPollManager::create();
    REQUIRE(result.has_value());
    auto& manager = result.value();

    int socket_pair[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair) == 0);
    sys::FD fd1; fd1.reset(socket_pair[0]);
    sys::FD fd2; fd2.reset(socket_pair[1]);

    bool triggered = false;
    EPollBinding binding;
    binding.context = &triggered;
    binding.on_event = [](void* ctx, uint32_t) {
        bool* flag = static_cast<bool*>(ctx);
        *flag = true;
    };

    manager.subscribe(fd1, EPOLLERR, &binding);

    // Close the other end to create an error condition
    fd2.reset(-1);

    manager.poll(POLL_TIMEOUT_MS);
    CHECK(triggered == true);
}

TEST_CASE("[Integration Test] - EPollManager stress test with many FDs", "[epoll][stress]") {
    auto result = sys::EPollManager::create();
    REQUIRE(result.has_value());
    auto& manager = result.value();

    constexpr int NUM_FDS = 1000000000; // Stress with more FDs than MAX_EVENTS
    std::vector<std::unique_ptr<MockService>> services;

    // 1️⃣ Create and subscribe all services
    for (int i = 0; i < NUM_FDS; ++i) {
        auto service = std::make_unique<MockService>();
        bool subscribed = manager.subscribe(service->fd, EPOLLIN, &service->binding);
        if (!subscribed) {
            break;
        }
        services.push_back(std::move(service));
    }

    const size_t subscribed_count = services.size();
    INFO("Number of services actually subscribed: " << subscribed_count);

    // 2️⃣ Signal all FDs
    for (auto& service : services) {
        service->signal();
    }

    // 3️⃣ Poll in a loop until all events are processed
    size_t total_triggered = 0;
    while (total_triggered < subscribed_count) {
        auto res = manager.poll(POLL_TIMEOUT_MS);
        REQUIRE(res.has_value());
        total_triggered += res.value();
    }

    CHECK(total_triggered == subscribed_count);

    // 4️⃣ Verify all callbacks fired
    for (auto& service : services) {
        CHECK(service->triggered == true);
    }
}

TEST_CASE("[Integration Test] - EPollManager - Handles combined IN and OUT flags", "[epoll]") {
    auto manager = sys::EPollManager::create().value();
    MockService service;

    // 1. Setup a socket pair (Remote -> Local)
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    sys::FD local{sv[0]}, remote{sv[1]};

    // 2. Subscribe to both Read and Write
    uint32_t received_mask = 0;
    service.binding.context = &received_mask;
    service.binding.on_event = [](void* ctx, uint32_t events) {
        *static_cast<uint32_t*>(ctx) = events;
    };

    manager.subscribe(local, EPOLLIN | EPOLLOUT, &service.binding);

    // 3. Make it readable by sending data from the remote side
    uint64_t data = 1;
    write(remote.get(), &data, sizeof(data));

    // 4. Poll and verify
    manager.poll(POLL_TIMEOUT_MS);
    
    CHECK((received_mask & EPOLLIN));  // Ready to read?
    CHECK((received_mask & EPOLLOUT)); // Ready to write?
}

TEST_CASE("[Integration Test] - EPollManager - Update existing subscription", "[epoll]") {
    auto manager = sys::EPollManager::create().value();
    MockService service;

    // Start with only OUT
    manager.subscribe(service.fd, EPOLLOUT, &service.binding);
    
    // Update to only IN
    bool updated = manager.subscribe(service.fd, EPOLLIN, &service.binding);
    
    CHECK(updated == true);
    
    // Signal and verify it still works after the update
    service.signal();
    manager.poll(POLL_TIMEOUT_MS);
    CHECK(service.triggered == true);
}

TEST_CASE("[Integration Test] - Resilience to System Interrupts", "[epoll]") {
    // 1. Setup with SA_RESTART so your poll() doesn't need a while loop
    struct sigaction sa;
    sa.sa_handler = [](int) {}; 
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // The Kernel handles the "loop" for you
    
    struct sigaction old_sa;
    sigaction(SIGALRM, &sa, &old_sa); // Save old state to be a good citizen

    auto result = sys::EPollManager::create();
    REQUIRE(result.has_value());
    auto& manager = result.value();

    // 2. Use a longer delay (10ms) to ensure we are actually "inside" poll
    // when the signal hits.
    ualarm(10000, 0); 

    auto start = std::chrono::steady_clock::now();
    auto res = manager.poll(50); 
    auto end = std::chrono::steady_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // 3. Verification
    CHECK(res.has_value());
    CHECK(duration >= 45); // This proves the kernel resumed the wait
    
    // 4. Cleanup
    ualarm(0, 0);
    sigaction(SIGALRM, &old_sa, nullptr); // Restore original signal handler
}

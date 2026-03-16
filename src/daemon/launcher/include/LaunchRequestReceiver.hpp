#include "common/GameID.hpp"
#include "system/FD.hpp"

class LaunchRequestReceiver {
private:
    sys::FD server_fd;
public:
    LaunchRequestReceiver();
    LaunchRequestReceiver(LaunchRequestReceiver &&) = delete;
    LaunchRequestReceiver(const LaunchRequestReceiver &) = delete;
    LaunchRequestReceiver &operator=(LaunchRequestReceiver &&) = delete;
    LaunchRequestReceiver &operator=(const LaunchRequestReceiver &) = delete;
    ~LaunchRequestReceiver();

    bool start();
    common::GameID waitForGameID();
};

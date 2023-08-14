#include "ConnectionHandler.h"
#include <signal.h>

volatile bool run_server = true;

void handle_sigint(int sig) {
    run_server = false;
}

int main() {
    signal(SIGINT, handle_sigint);

    ConnectionHandler server;

    if (!server.start()) {
        std::cerr << "Server failed to start\n";
        return -1;
    }

    while (run_server) {
        // Server processing logic
    }

    server.stop();
    return 0;
}

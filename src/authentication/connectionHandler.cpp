#include "ConnectionHandler.h"
#include "authentication.h"

ConnectionHandler::ConnectionHandler() : server_fd(0), new_socket(0), address() {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(5000);
}

ConnectionHandler::~ConnectionHandler() {
    close(server_fd);
}

// ... rest of the implementation ...

void ConnectionHandler::handleRegisterRequest(const std::string& received) {
    // handle register logic, use Authentication::hashPassword
}

void ConnectionHandler::handleLoginRequest(const std::string& received) {
    // handle login logic, use Authentication::verifyPassword and Authentication::generateToken
}

bool ConnectionHandler::validateToken(const std::string& token) {
    return Authentication::validateToken(token);
}

// ... other member functions as previously provided ...

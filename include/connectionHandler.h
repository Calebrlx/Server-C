#pragma once

#include <iostream>
#include <string>
#include <map>
#include <unordered_map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "nlohmann/json.hpp"

class ConnectionHandler {
public:
    ConnectionHandler();
    ~ConnectionHandler();
    bool start();
    void stop();

private:
    int server_fd;
    int new_socket;
    sockaddr_in address;
    std::map<std::string, std::string> users; // Username and hashed password mapping
    std::unordered_map<std::string, std::string> active_tokens; // Active tokens with associated usernames

    std::string extractJsonBody(const std::string& request);
    void sendJsonResponse(int client_socket, const nlohmann::json& json, int status_code);
    void sendErrorResponse(int client_socket, const std::string& message, int status_code);
    void sendSuccessResponse(int client_socket, const std::string& message);
    void handleClient(int client_socket);
    void handleRegisterRequest(int client_socket, const std::string& received);
    void handleLoginRequest(int client_socket, const std::string& received);
    std::string extractJsonBody(const std::string& request);
    bool validateToken(const std::string& token); // Function to validate tokens
};

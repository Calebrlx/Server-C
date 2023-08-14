#include "connectionHandler.h"
#include "authentication.h"
#include <thread>
#include <iostream>
#include <string> 
#include <sys/socket.h>

ConnectionHandler::ConnectionHandler() : server_fd(0), new_socket(0), address() {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(5000);
}

ConnectionHandler::~ConnectionHandler() {
    close(server_fd);
}

bool ConnectionHandler::start() {
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed\n";
        return false;
    }

    if (listen(server_fd, 3) < 0) {
        std::cerr << "Listen failed\n";
        return false;
    }

    while (true) {
        socklen_t addrlen = sizeof(address);
        new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (new_socket < 0) {
            std::cerr << "Accept failed\n";
            return false;
        }

        // Create a separate thread to handle each client connection
        std::thread client_thread(&ConnectionHandler::handleClient, this, new_socket);
        client_thread.detach(); // Detach the thread so it can continue independently
    }
    return true;
}

void ConnectionHandler::stop() {
    close(new_socket);
}

void ConnectionHandler::handleClient(int client_socket) {
    char buffer[1024] = {0};
    ssize_t bytesRead = read(client_socket, buffer, 1023);
    if (bytesRead < 0) {
        // Handle error reading from socket
        close(client_socket);
        return;
    }
    std::string received(buffer, bytesRead);

    if (received.find("/register") != std::string::npos) {
        handleRegisterRequest(client_socket, received);
    } else if (received.find("/login") != std::string::npos) {
        handleLoginRequest(client_socket, received);
    }

    close(client_socket); // Close the connection
}
void ConnectionHandler::handleRegisterRequest(int client_socket, const std::string& received) {
    std::string json_str = extractJsonBody(received);
    if (json_str.empty()) {
        sendErrorResponse(client_socket, "Invalid request body", 400);
        return;
    }

    nlohmann::json json_obj;
    try {
        json_obj = nlohmann::json::parse(json_str);
    } catch (const nlohmann::json::exception& e) {
        sendErrorResponse(client_socket, "Invalid JSON", 400);
        return;
    }

    if (!json_obj.contains("username") || !json_obj.contains("password")) {
        sendErrorResponse(client_socket, "Missing username or password", 400);
        return;
    }
    
    std::string username = json_obj["username"];
    std::string password = json_obj["password"];

    if (users.find(username) != users.end()) {
        sendErrorResponse(client_socket, "User already exists", 400);
        return;
    }

    std::string hashed_pw = Authentication::hashPassword(password);
    if (hashed_pw.empty()) {
        sendErrorResponse(client_socket, "Password hashing error", 500);
        return;
    }

    users[username] = hashed_pw;
    sendSuccessResponse(client_socket, "Registration successful");
}

void ConnectionHandler::handleLoginRequest(int client_socket, const std::string& received) {
    std::string json_str = extractJsonBody(received);
    if (json_str.empty()) {
        sendErrorResponse(client_socket, "Invalid request body", 400);
        return;
    }

    nlohmann::json json_obj;
    try {
        json_obj = nlohmann::json::parse(json_str);
    } catch (const nlohmann::json::exception& e) {
        sendErrorResponse(client_socket, "Invalid JSON", 400);
        return;
    }

    if (!json_obj.contains("username") || !json_obj.contains("password")) {
        sendErrorResponse(client_socket, "Missing username or password", 400);
        return;
    }

    std::string username = json_obj["username"];
    std::string password = json_obj["password"];

    if (users.find(username) == users.end() || !Authentication::verifyPassword(password, users[username])) {
        sendErrorResponse(client_socket, "Invalid credentials", 401);
        return;
    }

    std::string token = Authentication::generateToken(username);
    nlohmann::json response;
    response["success"] = true;
    response["message"] = "Login successful";
    response["token"] = token;
    active_tokens[username] = token;

    sendJsonResponse(client_socket, response, 200);
}

void ConnectionHandler::sendErrorResponse(int client_socket, const std::string& message, int status_code) {
    nlohmann::json response;
    response["success"] = false;
    response["error"] = message;

    sendJsonResponse(client_socket, response, status_code);
}

void ConnectionHandler::sendSuccessResponse(int client_socket, const std::string& message) {
    nlohmann::json response;
    response["success"] = true;
    response["message"] = message;

    sendJsonResponse(client_socket, response, 200);
}

void ConnectionHandler::sendJsonResponse(int client_socket, const nlohmann::json& json, int status_code) {
    std::string response_body = json.dump();
    std::string response = "HTTP/1.1 " + std::to_string(status_code) + " OK\r\n";
    response += "Content-Type: application/json\r\n";
    response += "Content-Length: " + std::to_string(response_body.size()) + "\r\n\r\n";
    response += response_body;

    send(client_socket, response.c_str(), response.size(), 0);
}

bool ConnectionHandler::validateToken(const std::string& token) {
    return Authentication::validateToken(token);
}

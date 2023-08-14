#pragma once

#include <string>
#include <memory>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include "nlohmann/json.hpp"

class UserManager {
public:
    UserManager();
    ~UserManager();
    bool registerUser(const nlohmann::json& userData);
    bool loginUser(const nlohmann::json& credentials, std::string& token);

private:
    std::unique_ptr<sql::Connection> con;
    bool connectToDatabase();
};

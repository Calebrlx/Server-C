#pragma once

#include <string>
#include "jwt-cpp/jwt.h"
#include "nlohmann/json.hpp"

namespace Authentication {

    std::string generateToken(const std::string& username);

    bool validateToken(const std::string& token);

    std::string hashPassword(const std::string& password);

    bool verifyPassword(const std::string& password, const std::string& hashed_password);
}

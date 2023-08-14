#include "authentication.h"
#include "userManager.h"
#include <random>
#include <iostream>
#include <cstdlib>
#include <bcrypt/BCrypt.hpp>
#include <jwt-cpp/jwt.h>
#include <chrono>

namespace Authentication {
    std::string secret_key = std::getenv("SECRET_KEY");

    std::string generateToken(const std::string& username) {
        auto token = jwt::create()
            .set_issuer("auth0")
            .set_subject(username)
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours{1})
            .sign(jwt::algorithm::hs256{secret_key});
        return token;
    }

    bool validateToken(const std::string& token) {
        try {
            auto decoded_token = jwt::decode(token);
            auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{secret_key})
                .with_issuer("auth0");
            verifier.verify(decoded_token);
            return true; // token is valid
        } catch (const std::exception& e) {
            std::cerr << "Token validation error: " << e.what() << '\n';
            return false; // token is not valid
        }
    }

    std::string hashPassword(const std::string& password) {
        return BCrypt::generateHash(password);
    }

    bool verifyPassword(const std::string& password, const std::string& hashed_password) {
        return BCrypt::validatePassword(password, hashed_password);
    }
}

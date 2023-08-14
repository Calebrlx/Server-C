#include "authentication.h"
#include "userManager.h"
#include <crypt.h>
#include <random>
#include <iostream>

namespace Authentication {
    std::string generateToken(const std::string& username) {
        auto token = jwt::create()
            .set_issuer("auth0")
            .set_subject(username)
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours{1})
            .sign(jwt::algorithm::hs256{"your_secret_key"});
        return token;
    }

    bool validateToken(const std::string& token) {
        try {
            auto decoded_token = jwt::decode(token);
            auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{"your_secret_key"})
                .with_issuer("auth0");
            verifier.verify(decoded_token);
            return true; // token is valid
        } catch (const std::exception& e) {
            std::cerr << "Token validation error: " << e.what() << '\n';
            return false; // token is not valid
        }
    }

    std::string hashPassword(const std::string& password) {
        std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::random_device random_device;
        std::mt19937 generator(random_device());
        std::uniform_int_distribution<> distribution(0, characters.size() - 1);

        std::string random_salt;
        for (std::size_t i = 0; i < 22; ++i) {
            random_salt += characters[distribution(generator)];
        }

        std::string salt = "$2a$05$" + random_salt;

        const char* hashed_pw_cstr = crypt(password.c_str(), salt.c_str());
        if (!hashed_pw_cstr) {
            std::cerr << "Error hashing password\n";
            return "";
        }
        return hashed_pw_cstr;
    }

    bool verifyPassword(const std::string& password, const std::string& hashed_password) {
        std::string salt = hashed_password.substr(0, 29); // Extract salt from stored hash
        const char* hashed_input_pw_cstr = crypt(password.c_str(), salt.c_str());
        if (!hashed_input_pw_cstr) {
            return false;
        }
        return hashed_input_pw_cstr == hashed_password;
    }
}

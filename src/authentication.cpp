#include "authentication.h"
#include "userManager.h"
#include <random>
#include <iostream>
#include <cstdlib>
#include "bcrypt.h"
#include <jwt-cpp/jwt.h>
#include <chrono>

namespace Authentication {
    const char* secret_key_env = std::getenv("SECRET_KEY");
    std::string secret_key;

    if (secret_key_env != nullptr) {
        secret_key = secret_key_env;
    } else {
        // Handle the case where the environment variable is not set
        std::cerr << "Error: SECRET_KEY environment variable not set." << std::endl;
        // You may choose to exit the program or handle the error in another way
    }


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
        char salt[BCRYPT_HASHSIZE];
        char hash[BCRYPT_HASHSIZE];
    
        bcrypt_gensalt(12, salt);
        bcrypt_hashpw(password.c_str(), salt, hash);
    
        return std::string(hash);
    }
    
    bool verifyPassword(const std::string& password, const std::string& hashed_password) {
        return bcrypt_checkpw(password.c_str(), hashed_password.c_str()) == 0;
    }
}

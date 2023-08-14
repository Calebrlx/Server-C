#include "authentication.h"
#include "userManager.h"
#include <random>
#include <iostream>
#include <cstdlib>
#include "bcrypt.h"
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
        return bcrypt::generateHash(password);
    }

    bool verifyPassword(const std::string& password, const std::string& hashed_password) {
        return bcrypt::validatePassword(password, hashed_password);
    }


    std::string bcrypt::generateHash(const std::string &password, unsigned int rounds) {
        char salt[_SALT_LEN];
    
        unsigned char seed[17]{};
    	arc4random_init();
    	
        arc4random_buf(seed, 16);
    
        bcrypt_gensalt('b', rounds, seed, salt);
    
        std::string hash(61, '\0');
        node_bcrypt(password.c_str(), password.size(), salt, &hash[0]);
        hash.resize(60);
        return hash;
    }
    
    bool bcrypt::validatePassword(const std::string &password, const std::string &hash) {
        std::string got(61, '\0');
        node_bcrypt(password.c_str(), password.size(), hash.c_str(), &got[0]);
        got.resize(60);
        return hash == got;
    }
}

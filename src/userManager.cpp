#include "userManager.h"
#include "authentication.h"
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>


const char* MySQL_user_env = std::getenv("MYSQL_USER");
const char* MySQL_pass_env = std::getenv("MYSQL_PASS");

UserManager::UserManager() {
    connectToDatabase();
}

UserManager::~UserManager() {
    if (con) {
        con->close();
    }
}

bool UserManager::connectToDatabase() {
    try {
        sql::mysql::MySQL_Driver* driver;
        driver = sql::mysql::get_mysql_driver_instance();
        con.reset(driver->connect("tcp://10.0.0.40:3306", MySQL_user_env, MySQL_pass_env));
        con->setSchema("database_name");
        return true;
    } catch (const sql::SQLException& e) {
        std::cerr << "Database connection error: " << e.what() << std::endl;
        return false;
    }
}

bool UserManager::registerUser(const nlohmann::json& userData) {
    try {
        sql::PreparedStatement* pstmt = con->prepareStatement(
            "INSERT INTO users (username, password, subscription_status, first_name, last_name, email) "
            "VALUES (?, ?, ?, ?, ?, ?)");
        pstmt->setString(1, userData["username"]);
        pstmt->setString(2, Authentication::hashPassword(userData["password"]));
        pstmt->setInt(3, userData["subscription_status"]);
        pstmt->setString(4, userData["first_name"]);
        pstmt->setString(5, userData["last_name"]);
        pstmt->setString(6, userData["email"]);
        pstmt->executeUpdate();
        delete pstmt;
        return true;
    } catch (const sql::SQLException& e) {
        std::cerr << "User registration error: " << e.what() << std::endl;
        return false;
    }
}

bool UserManager::loginUser(const nlohmann::json& credentials, std::string& token) {
    try {
        sql::PreparedStatement* pstmt = con->prepareStatement(
            "SELECT password FROM users WHERE username = ?");
        pstmt->setString(1, credentials["username"]);
        sql::ResultSet* res = pstmt->executeQuery();

        if (res->next()) {
            std::string stored_hashed_password = res->getString("password");
            if (Authentication::verifyPassword(credentials["password"], stored_hashed_password)) {
                token = Authentication::generateToken(credentials["username"]);
                delete res;
                delete pstmt;
                std::cout << "Authentication success for user: " << credentials["username"] << " | pass: " << credentials["password"] << '\n';
                return true;
            } else {
                std::cout << "Authentication failed for user: " << credentials["username"] << " | pass: " << credentials["password"] << '\n';
            }
        }

        delete res;
        delete pstmt;
        return false;
    } catch (const sql::SQLException& e) {
        std::cerr << "User login error: " << e.what() << std::endl;
        return false;
    }
}


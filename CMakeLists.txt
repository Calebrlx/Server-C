cmake_minimum_required(VERSION 3.10)

# Set the project name and version
project(MyServerApp VERSION 1.0)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(THREADS_PREFER_PTHREAD_FLAG ON)

# Include FetchContent module
include(FetchContent)

# Include the nlohmann JSON library using FetchContent
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.10.4
)
FetchContent_MakeAvailable(nlohmann_json)

include_directories("/usr/local/include/jwt-cpp")
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories("~/libbcrypt")
include_directories("/usr/include")

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig)

# Find the MySQL Connector/C++ library
find_library(MYSQLCPPCONN_LIBRARIES
             NAMES mysqlcppconn
             HINTS /usr/lib /usr/local/lib)

# Define the executable target
add_executable(MyServerApp src/main.cpp src/connectionHandler.cpp src/authentication.cpp src/userManager.cpp)

target_link_libraries(MyServerApp PRIVATE
  OpenSSL::SSL OpenSSL::Crypto
  Threads::Threads
  nlohmann_json::nlohmann_json
  -lcrypt
  /usr/local/lib/bcrypt.a
  ${MYSQLCPPCONN_LIBRARIES}) # Inside the target_link_libraries command


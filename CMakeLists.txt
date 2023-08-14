cmake_minimum_required(VERSION 3.10)

# Set the project name and version
project(MyServerApp VERSION 1.0)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include FetchContent module
include(FetchContent)

# Include the nlohmann JSON library using FetchContent
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.10.4
)
FetchContent_MakeAvailable(nlohmann_json)

# Include the directories for headers
include_directories("/usr/local/include/jwt-cpp")
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_SOURCE_DIR}/include)

find_package(OpenSSL REQUIRED)
target_link_libraries(MyServerApp PRIVATE OpenSSL::SSL OpenSSL::Crypto)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(MyServerApp PRIVATE Threads::Threads)

# Define the executable target
add_executable(MyServerApp src/main.cpp src/connectionHandler.cpp src/authentication.cpp)

# Link the libraries
target_link_libraries(MyServerApp PRIVATE nlohmann_json::nlohmann_json -lcrypt)

cmake_minimum_required(VERSION 3.10)

# Set the project name and version
project(MyServerApp VERSION 1.0)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include the jwt-cpp library
include_directories("/usr/local/include/jwt-cpp")

# If you need to include nlohmann_json, you can fetch it directly using FetchContent
include(FetchContent)
FetchContent_Declare(
  nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.9.1/include.zip
)
FetchContent_MakeAvailable(nlohmann_json)

# Include the directories for headers
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${nlohmann_json_SOURCE_DIR})

# Define the executable target
add_executable(MyServerApp main.cpp ConnectionHandler.cpp authentication.cpp)

# Link the libraries
target_link_libraries(MyServerApp -lcrypt)

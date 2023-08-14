cmake_minimum_required(VERSION 3.10)

# Set the project name and version
project(MyServerApp VERSION 1.0)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include the jwt-cpp library and nlohmann JSON
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBJWT REQUIRED IMPORTED_TARGET jwt-cpp nlohmann_json)

# Include the directories for headers
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Define the executable target
add_executable(MyServerApp src/main.cpp src/ConnectionHandler.cpp src/authentication.cpp)

# Link the libraries
target_link_libraries(MyServerApp PRIVATE PkgConfig::LIBJWT -lcrypt)

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
include_directories(${MYSQLCONNECTORCPP_INCLUDE_DIRS})
include_directories("/usr/include")
link_directories(${MYSQLCONNECTORCPP_LIBRARY_DIRS})

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Define the executable target
add_executable(MyServerApp src/main.cpp src/connectionHandler.cpp src/authentication.cpp src/userManager.cpp src/bcrypt.cpp)

# Link the libraries
target_link_libraries(MyServerApp PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(MyServerApp PRIVATE Threads::Threads)
target_link_libraries(MyServerApp PRIVATE nlohmann_json::nlohmann_json -lcrypt)
target_link_libraries(MyServerApp PRIVATE /usr/local/lib/libbcrypt.a) # Link to libbcrypt
target_link_libraries(MyServerApp ${MYSQLCONNECTORCPP_LIBRARIES})
target_link_libraries(MyServerApp "/usr/lib/aarch64-linux-gnu/libmysqlcppconn.so")
target_link_libraries(MyServerApp PRIVATE "/usr/lib/aarch64-linux-gnu/libmysqlcppconn.so"
    # other libraries...
)


cmake_minimum_required(VERSION 3.12)
project(PlayLab VERSION 0.0.1)

set(SEALExamples_SOURCE_DIR <PATH_TO_SEAL/NATIVE/EXAMPLES>)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(PlayLab playlab.cpp)
add_executable(string_HE_test string_HE_test.cpp)

find_package(SEAL 3.4.5 EXACT REQUIRED
    # Providing a path so this can be built without installing Microsoft SEAL
    PATHS ${SEALExamples_SOURCE_DIR}/../src/cmake
)

# Link Microsoft SEAL
target_link_libraries(PlayLab SEAL::seal)
target_link_libraries(string_HE_test SEAL::seal)
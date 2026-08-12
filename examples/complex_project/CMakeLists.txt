cmake_minimum_required(VERSION 3.16)
project(mini_re_complex_project LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(scoring STATIC src/analyzer.cpp src/helpers.cpp)
target_include_directories(scoring PUBLIC include)
target_compile_options(scoring PRIVATE -Wall -Wextra -Wpedantic)

add_executable(scoring_cli app/main.cpp)
target_link_libraries(scoring_cli PRIVATE scoring)

enable_testing()
add_executable(scoring_unit_tests tests/unit_tests.cpp)
target_link_libraries(scoring_unit_tests PRIVATE scoring)
add_test(NAME scoring_unit_tests COMMAND scoring_unit_tests)

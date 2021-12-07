project(MULE_DEMO CXX)
cmake_minimum_required(VERSION 3.10)

add_compile_options( -std=c++17 )

include_directories(
    ${PROJECT_SOURCE_DIR}/deploy/LogIt/include
	$ENV{BOOST_HEADERS}
	../include/
    ../../LogIt/include
	)

file(GLOB SOURCES ../src/*.cpp)

add_library( this OBJECT ${SOURCES})

add_executable(
	demo
	demo.cpp
	$<TARGET_OBJECTS:this>
	)

set(COMMON_LIBS
	${PROJECT_SOURCE_DIR}/deploy/LogIt/lib/libLogIt.a
    -lnetsnmp
	)

target_link_libraries(
	demo
    ${COMMON_LIBS}
	)
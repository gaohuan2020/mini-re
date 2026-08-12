CXX ?= c++
AR ?= ar
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -Iinclude

LIB_OBJECTS = build/analyzer.o build/helpers.o

.PHONY: all clean test runtime

all: build/libscoring.a build/scoring_cli build/scoring_unit_tests

build:
	mkdir -p build

build/analyzer.o: src/analyzer.cpp include/scoring/analyzer.hpp | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/helpers.o: src/helpers.cpp include/scoring/analyzer.hpp | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/libscoring.a: $(LIB_OBJECTS)
	$(AR) rcs $@ $^

build/scoring_cli: app/main.cpp build/libscoring.a
	$(CXX) $(CXXFLAGS) $< build/libscoring.a -o $@

build/scoring_unit_tests: tests/unit_tests.cpp build/libscoring.a
	$(CXX) $(CXXFLAGS) $< build/libscoring.a -o $@

test: build/scoring_unit_tests
	./build/scoring_unit_tests

runtime: build/scoring_cli
	./build/scoring_cli --self-test

clean:
	rm -rf build

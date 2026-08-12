#include "scoring/analyzer.hpp"

#include <iostream>
#include <string>
#include <vector>

int main(int argc, char **argv) {
    if (argc != 2 || std::string(argv[1]) != "--self-test") {
        std::cerr << "usage: scoring_cli --self-test\n";
        return 2;
    }

    scoring::Analyzer analyzer;
    scoring::Options clamped{7, true, 1};
    scoring::Options plain{3, false, 0};
    const std::vector<int> mixed{4, -3, 8, 8, 1200, -6};
    const std::vector<int> positive{2, 2, 5};

    if (analyzer.score(mixed, clamped) != 2035) {
        std::cerr << "clamped vector score mismatch\n";
        return 1;
    }
    if (analyzer.score(positive, plain) != 49) {
        std::cerr << "plain vector score mismatch\n";
        return 1;
    }
    if (analyzer.score(1200) != 1001) {
        std::cerr << "scalar overload changed\n";
        return 1;
    }
    std::cout << "runtime behavior passed\n";
    return 0;
}

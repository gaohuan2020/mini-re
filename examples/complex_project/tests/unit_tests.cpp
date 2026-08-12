#include "scoring/analyzer.hpp"

#include <cassert>

int main() {
    assert(scoring::normalize(-2000) == -1000);
    assert(scoring::normalize(42) == 42);
    assert(scoring::normalize(2000) == 1000);
    assert(scoring::bucket_weight(0) == 3);
    assert(scoring::bucket_weight(2) == 5);
    assert(scoring::bucket_weight(7) == -2);

    scoring::Analyzer analyzer;
    assert(analyzer.score(1200) == 1001);
    return 0;
}

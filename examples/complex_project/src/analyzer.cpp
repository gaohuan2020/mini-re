#include "scoring/analyzer.hpp"

namespace scoring {

int Analyzer::score(const std::vector<int> &samples, const Options &options) const {
    (void)samples;
    (void)options;
    return -999;
}

int Analyzer::score(int sample) const {
    return normalize(sample) + 1;
}

}  // namespace scoring

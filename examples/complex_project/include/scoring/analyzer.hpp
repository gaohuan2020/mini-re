#pragma once

#include <cstddef>
#include <vector>

namespace scoring {

struct Options {
    int bias = 0;
    bool clamp_negative = false;
    unsigned window = 0;
};

int normalize(int value);
int bucket_weight(std::size_t index);

class Analyzer {
public:
    int score(const std::vector<int> &samples, const Options &options) const;
    int score(int sample) const;
};

}  // namespace scoring

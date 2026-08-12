#include "scoring/analyzer.hpp"

namespace scoring {

int normalize(int value) {
    if (value < -1000) {
        return -1000;
    }
    if (value > 1000) {
        return 1000;
    }
    return value;
}

int bucket_weight(std::size_t index) {
    static const int weights[] = {3, 2, 5, -2};
    return weights[index & 3u];
}

}  // namespace scoring

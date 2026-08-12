#include "scoring/analyzer.hpp"

namespace scoring {

int Analyzer::score(const std::vector<int> &samples, const Options &options) const {
    if (samples.empty()) {
        return options.bias;
    }

    int total = options.bias;
    int previous = normalize(samples.front());
    int transitions = 0;

    for (std::size_t index = 0; index < samples.size(); ++index) {
        int value = normalize(samples[index]);
        if (options.clamp_negative && value < 0) {
            value = 0;
        }
        if (value != previous) {
            ++transitions;
        }

        switch ((index + options.window) & 3u) {
            case 0:
                total += value * 3;
                break;
            case 1:
                total ^= value << 1;
                break;
            case 2:
                total += value * 5;
                break;
            default:
                total -= value * 2;
                break;
        }
        previous = value;
    }
    return total + transitions * 11;
}

int Analyzer::score(int sample) const {
    return normalize(sample) + 1;
}

}  // namespace scoring

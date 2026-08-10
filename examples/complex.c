#include <stddef.h>
#include <stdint.h>

typedef struct AnalysisStats {
    int64_t weighted_sum;
    int32_t minimum;
    int32_t maximum;
    uint32_t transitions;
    uint32_t histogram[8];
} AnalysisStats;

uint32_t rolling_hash(const uint8_t *data, size_t length, uint32_t seed) {
    uint32_t hash = seed ^ 0x9e3779b9u;
    for (size_t index = 0; index < length; ++index) {
        hash ^= data[index];
        hash *= 16777619u;
        hash = (hash << 5) | (hash >> 27);
        if ((index & 3u) == 3u) {
            hash ^= hash >> 13;
        }
    }
    return hash;
}
int analyze_samples(const int16_t *samples, size_t count, AnalysisStats *stats) {
    if (samples == NULL || stats == NULL || count == 0) {
        return -1;
    }

    stats->weighted_sum = 0;
    stats->minimum = samples[0];
    stats->maximum = samples[0];
    stats->transitions = 0;
    for (size_t bucket = 0; bucket < 8; ++bucket) {
        stats->histogram[bucket] = 0;
    }

    int16_t previous = samples[0];
    for (size_t index = 0; index < count; ++index) {
        int32_t value = samples[index];
        if (value < stats->minimum) {
            stats->minimum = value;
        } else if (value > stats->maximum) {
            stats->maximum = value;
        }

        if ((value < 0) != (previous < 0)) {
            ++stats->transitions;
        }
        previous = (int16_t)value;

        uint32_t magnitude = value < 0 ? (uint32_t)(-value) : (uint32_t)value;
        uint32_t bucket = magnitude >> 12;
        if (bucket > 7) {
            bucket = 7;
        }
        ++stats->histogram[bucket];

        switch (index & 3u) {
            case 0:
                stats->weighted_sum += value;
                break;
            case 1:
                stats->weighted_sum -= (int64_t)value * 3;
                break;
            case 2:
                stats->weighted_sum += (int64_t)value * 5;
                break;
            default:
                stats->weighted_sum ^= (int64_t)(uint32_t)value << 7;
                break;
        }
    }

    return stats->maximum - stats->minimum;
}

struct MatrixStats {
    long long sum;
    int minimum;
    int maximum;
};

int overloaded(int value) {
    return value < 0 ? -value : value;
}

double overloaded(double value) {
    return value * 1.5;
}

extern "C" int matrix_entry(const int *values, int count, MatrixStats *stats) {
    if (values == nullptr || stats == nullptr || count <= 0) {
        return -1;
    }
    stats->sum = 0;
    stats->minimum = values[0];
    stats->maximum = values[0];
    for (int index = 0; index < count; ++index) {
        int value = values[index];
        stats->sum += value;
        if (value < stats->minimum) {
            stats->minimum = value;
        } else if (value > stats->maximum) {
            stats->maximum = value;
        }
    }
    return stats->maximum - stats->minimum;
}

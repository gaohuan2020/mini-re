int clamp_add(int value, int delta) {
    int result = value + delta;
    if (result < 0) {
        return 0;
    }
    if (result > 100) {
        return 100;
    }
    return result;
}

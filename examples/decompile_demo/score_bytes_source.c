/* Source used to build score_bytes.o. It is kept only for comparison. */
int score_bytes(const unsigned char *data, unsigned long length, int seed) {
    unsigned int accumulator;
    unsigned char previous;
    int transitions = 0;

    if (data == 0 || length == 0) {
        return -1;
    }

    accumulator = (unsigned int)seed ^ 0x9e3779b9u;
    previous = data[0];

    for (unsigned long index = 0; index < length; ++index) {
        unsigned int value = data[index];

        if ((unsigned char)value != previous) {
            ++transitions;
        }

        switch (index & 3u) {
            case 0:
                accumulator += value * 3u;
                break;
            case 1:
                accumulator ^= value << 5;
                break;
            case 2:
                accumulator = (accumulator << 7) | (accumulator >> 25);
                accumulator += value;
                break;
            default:
                accumulator -= value * 7u;
                break;
        }

        previous = (unsigned char)value;
    }

    return (int)((accumulator ^ (unsigned int)transitions) & 0x7fffffffu);
}

#include <stdio.h>

float magnitude2(float x, float y, float z) {
    return x * x + y * y;
}

void test(float x, float y, float z) {
    float mag2 = magnitude2(x, y, z);
    printf("The square magnitude of the vector (%f, %f, %f) is %f\n", x, y, z, mag2);
}

void main() {
    test(0.0f, 0.0f, 0.0f);
    test(1.0f, 2.0f, 3.0f);
    test(-20.0f, 33.2f, 5.2f);
    test(3.0f, 4.0f, 0.0f);
}
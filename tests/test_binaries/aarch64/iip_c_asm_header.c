#include <stdio.h>

void print_areas(float *radii, float *areas, int num_circles) {
    for (int i = 0; i < num_circles; i++) {
        printf("The area of the circle with radius %f is %f\n", radii[i], areas[i]);
    }
}

void compute_areas(float *radii, int num_radii) {
    float areas[num_radii];
    for (int i = 0; i < num_radii; i++) {
        // Error is here! We should have multiplied by another radius, but we forgot :(
        areas[i] = 3.14 * radii[i];
    }
    print_areas(radii, areas, num_radii);
}

void main() {
    float radii[3] = { 1.5, 2.0, 4.3 };
    compute_areas(radii, 3);
}
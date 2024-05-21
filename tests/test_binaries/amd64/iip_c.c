#include <stdint.h>
#include <stdio.h>

uint32_t add_2_then_double(uint32_t n) {
  uint32_t ret = n + 2;
  ret *= 2;
  return ret;
}

int main(int argc, char *argv[]) {
  uint32_t num = add_2_then_double(4);
  printf("%d", num);
  return 0;
}

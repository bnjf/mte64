#include <stdint.h>
#include <stdlib.h>

#include "rnd.h"

static uint16_t rnd_x;
static uint16_t rnd_c;

long rnd_n(const int n) {
  uint16_t x, r;
  do {
    x = rnd();
    r = x % n;
  } while (x - r > (-n));
  return r;
}

void rnd_init(const uint32_t x) {
  rnd_x = x & 0xffff;
  rnd_c = x >> 16;
}

long rnd() {
  uint32_t t = 0xfea0UL * rnd_x + rnd_c;
  rnd_x = t & 0xffff;
  rnd_c = t >> 16;
  return rnd_x;
}

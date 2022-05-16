#include <stdint.h>
#include <stdlib.h>

#include "rnd.h"

static uint16_t rnd_x;
static uint16_t rnd_c;

long rnd_n(int n) {
  uint16_t x, r;
  do {
    x = rnd();
    r = x % n;
  } while (x - r > (-n));
  return r;
}

void rnd_init(uint32_t x) {
  rnd_x = x;
  rnd_c = x >> 16;
}

long rnd() {
  uint32_t t = 0xfea0UL * rnd_x + rnd_c;
  rnd_x = t;
  rnd_c = t >> 16;
  return rnd_x;
}

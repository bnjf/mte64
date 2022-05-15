#include <stdint.h>
#include <stdlib.h>

#include "rnd.h"

long rnd_n(int n) {
  long x, r;
  do {
    x = random();
    r = x % n;
  } while (x - r > (-n));
  return r;
}

static uint16_t rnd_orig_x;
static uint16_t rnd_orig_c;
void rnd_orig_init(uint16_t x, uint16_t c) {
  rnd_orig_x = x;
  rnd_orig_c = c;
}
uint16_t rnd_orig() {
  uint32_t t = 0xfea0UL * rnd_orig_x + rnd_orig_c;
  rnd_orig_x = t;
  rnd_orig_c = t >> 16;
  return rnd_orig_x;
}

#include <stdint.h>
#include <stdlib.h>

#include "rnd.h"

#define RAND_INV_RANGE(r) ((long int)((RAND_MAX + 1U) / (r)))

long int rnd_n(int RANGE) {
  long int x;
  do {
    x = random();
  } while (x >= RANGE * RAND_INV_RANGE(RANGE));
  x /= RAND_INV_RANGE(RANGE);
  return x;
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

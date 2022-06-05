#include <stdint.h>
#include <stdlib.h>

#include "rnd.h"

void rnd_init(uint32_t x) { srandom(x); }

uint32_t rnd_get() { return random(); }

uint32_t rnd_range(uint32_t n) {
  uint32_t x, r;
  do {
    x = rnd();
    r = x % n;
  } while (x - r > (-n));
  return r;
}

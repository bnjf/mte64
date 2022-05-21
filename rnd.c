#include <stdint.h>
#include <stdlib.h>

#include "rnd.h"

uint32_t rnd_n(uint32_t n) {
  uint32_t x, r;
  do {
    x = rnd();
    r = x % n;
  } while (x - r > (-n));
  return r;
}

void rnd_init(uint32_t x) { srandom(x); }
uint32_t rnd() { return random(); }

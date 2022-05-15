#include <stdint.h>
#include <stdlib.h>

#include "rnd.h"

long rnd_n(int n) {
  long x, r;
  do {
    x = rnd();
    r = x % n;
  } while (x - r > (-n));
  return r;
}

void rnd_init(unsigned x) { srandom(x); }
long rnd() { return random(); }

#include <stdlib.h>

#include "rnd.h"

#define RAND_INV_RANGE(r) ((long int)((RAND_MAX + 1U) / (r)))

long int rnd_n(int RANGE)
{
  long int x;
  do {
    x = random();
  } while (x >= RANGE * RAND_INV_RANGE(RANGE));
  x /= RAND_INV_RANGE(RANGE);
  return x;
}
#include <stdint.h>

#include "integer_inverse.h"

// https://arxiv.org/pdf/2204.04342.pdf
uint32_t integer_inverse(uint32_t a) {
  if (a % 2 == 0) {
    return 0;
  }
  uint32_t x0 = (3 * a) ^ 2; // See section 5, formula 3.
  uint32_t y = 1 - a * x0;
  uint32_t x1 = x0 * (1 + y);
  y *= y;
  uint32_t x2 = x1 * (1 + y);
  y *= y;
  uint32_t x3 = x2 * (1 + y);
  return x3;
  // only need 3 reps for u32:
  // https://lemire.me/blog/2017/09/18/computing-the-inverse-of-odd-integers/
  // y *= y;
  // uint32_t x4 = x3 * (1 + y);
  // return x4;
}

/* This file was automatically generated.  Do not edit! */
#undef INTERFACE
inline long int rnd_n(int RANGE){
  long int x;
  do {
    x = random();
  } while (x >= RANGE * RAND_INV_RANGE(RANGE));
  x /= RAND_INV_RANGE(RANGE);
  return x;
};

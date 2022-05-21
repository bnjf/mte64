
#define SWAP(x, y)                                                           \
  do {                                                                       \
    typeof(x) SWAP = x;                                                      \
    x = y;                                                                   \
    y = SWAP;                                                                \
  } while (0)

#if NDEBUG
#define D(...)
#else
#define D(...)                                                               \
  do {                                                                       \
    fprintf(stderr, "[%s L%u] ", __func__, __LINE__);                        \
    fprintf(stderr, __VA_ARGS__);                                            \
  } while (0)
#endif


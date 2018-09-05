#include "../include/hash.h"

extern TESLAParams params;

uint32_t hash_f(uint32_t *c, uint32_t *fc) {
  uint32_t i;
  uint32_t *shift = (uint32_t *)calloc(params.omega_pr, sizeof(uint32_t));
  if(shift == NULL) {
    debug(printf("calloc in hash_f failed.\n");)
  }
  for (i = 0; i < 16; i++) {
    shift[3*i] = c[i] & 0x3ff;
    shift[3*i+1] = (c[i] >> 10) & 0x3ff;
    shift[3*i+2] = (c[i] >> 20) & 0x3ff;
  }
  for (i = 0; i < 5; i++) {
    shift[48] += (c[i] >> (30 - 2*i)) & (0x3 << 2*i);
    shift[49] += (c[i+5] >> (30 - 2*i)) & (0x3 << 2*i);
    shift[50] += (c[i+10] >> (30 - 2*i)) & (0x3 << 2*i);
  }

  uint32_t count = 0;
  for (i = 0; i < params.omega_pr; i++) {
    if(fc[shift[i]] == 0) {
      fc[shift[i]] = 1;
      count++;
    }
    if(count == params.omega) {
      break;
    }
  }

  free(shift);

  if (count != params.omega) {
    return 1;
  } else {
    return 0;
  }
}

void d_rounding(uint32_t* x) {
  uint32_t m = 0xffffffff >> (32-params.d);
  uint32_t e = 0x1 << params.d;
  uint32_t tmp;
  for (size_t i = 0; i < params.n; i++) {
    tmp = x[i] & m;
    if(tmp > e/2) {
      tmp -= e;
    }
    x[i] = (x[i] - tmp) >> params.d;
  }
}

uint32_t l_norm_inf(uint32_t* x) {
  uint32_t max = 0, abs = 0;
  for (size_t i = 0; i < params.n; i++) {
    if(x[i] > (params.q-1)/2) {
      abs = params.q - x[i];
    }
    if(abs > max) {
      max = abs;
    }
  }
  return max;
}

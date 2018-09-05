#include "../include/random.h"

// Use ChaCha20 for PRNG
void chacha20_init(uint32_t *x, uint32_t *k) {
  x[0] = 0x61707876; // sigma1
  x[1] = 0x3320646e; // sigma2
  x[2] = 0x79622d32; // sigma3
  x[3] = 0x6b206574; // sigma4
  for (size_t i = 0; i < 8; i++) {
    x[i+4] = k[i];
  }
  for (size_t i = 0; i < 4; i++) {
    x[i+12] = 0;
  }
}

void chacha20_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
  *a += *b;
  *d ^= *a;
  *d = (*d << 16) | (*d >> (32-16));
  *c += *d;
  *b ^= *c;
  *b = (*b << 12) | (*b >> (32-12));
  *a += *b;
  *d ^= *a;
  *d = (*d << 8) | (*d >> (32-8));
  *c += *d;
  *b ^= *c;
  *b = (*b << 7) | (*b >> (32-7));
}

void prng(uint32_t len, uint32_t *a1, uint32_t *a2, uint32_t *seed, uint32_t mod) {
  uint32_t x[16], y[16];
  chacha20_init(x, seed);

  for (size_t i = 0; i < 2*len/16; i++) {
    memcpy((void*)y, (void*)x, 16*sizeof(uint32_t));
    // ChaCha20 Main Round
    for (size_t j = 0; j < 10; j++) {
      // Column Round
      chacha20_quarter_round(&x[0], &x[4], &x[8], &x[12]);
      chacha20_quarter_round(&x[5], &x[9], &x[13], &x[1]);
      chacha20_quarter_round(&x[10], &x[14], &x[2], &x[6]);
      chacha20_quarter_round(&x[15], &x[3], &x[7], &x[11]);
      // Diagonal Round
      chacha20_quarter_round(&x[0], &x[5], &x[10], &x[15]);
      chacha20_quarter_round(&x[1], &x[6], &x[11], &x[12]);
      chacha20_quarter_round(&x[2], &x[7], &x[8], &x[13]);
      chacha20_quarter_round(&x[3], &x[4], &x[9], &x[14]);
    }
    for (size_t j = 0; j < 16; j++) {
      x[j] += y[j];
    }
    if (i < len/16) {
      for (size_t j = 0; j < 16; j++) {
        a1[i*16+j] = x[j] % mod;
      }
    } else {
      for (size_t j = 0; j < 16; j++) {
        a2[i*16+j-len] = x[j] % mod;
      }
    }
  }
}

CK_RV mod_gaussian_sampling(
  CK_SESSION_HANDLE* h_session, float sigma, uint32_t len, uint32_t *sample, uint32_t mod
) {
  CK_RV rv;

  uint32_t *source = (uint32_t*)calloc(12*len, sizeof(uint32_t));
  if(source == NULL) {
    debug(printf("mod_gaussian_sampling: calloc failed\n");)
    return CKR_HOST_MEMORY;
  }

  rv = C_GenerateRandom(*h_session, (uint8_t*)source, 12*len*sizeof(uint32_t));
  if(rv != CKR_OK) {
    return rv;
  }

  float f;
  debug(printf("UINTMAX = %lu\n", UINT_MAX);)
  for (size_t i = 0; i < len; i++) {
    f = 0.0;
    for (size_t j = 0; j < 12; j++) {
      f += ((float)source[12*i+j]+1.0)/((float)UINT_MAX+2.0);
    }
    sample[i] = (uint32_t)((float)mod + (f - 6.0)*sigma) % mod;
    //sample[i] = (uint32_t)((float)mod + sqrtf(-2.0*logf(f1))*sinf(2.0*M_PI*f2)*sigma) % mod;
  }

  free(source);

  return rv;
}

CK_RV mod_sampling(CK_SESSION_HANDLE *h_session, uint32_t len, uint32_t *sample, uint32_t mod) {
  CK_RV rv = C_GenerateRandom(*h_session, (uint8_t*)sample, sizeof(uint32_t)*len);
  if(mod != 0) {
    for (size_t i = 0; i < len; i++) {
      sample[i] %= mod;
    }
  }
  return rv;
}

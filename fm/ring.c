// Fp, polynomial rings, and Number Theoritical Transform

#include "../include/ring.h"

extern TESLAParams params;

static uint32_t n_inv;
static uint32_t *omega;

// a < q and b < q
uint32_t mod_sub(uint32_t a, uint32_t b) {
  return (b > a) ? (a + params.q) - b : a - b;
}

uint32_t mod_add(uint32_t a, uint32_t b) {
  return (a + b) % params.q;
}

uint32_t mod_mul(uint32_t a, uint32_t b) {
  uint32_t a0 = a & 0x3fff;
  uint32_t a1 = a >> 14;
  uint32_t b0 = b & 0x3fff;
  uint32_t b1 = b >> 14;
  uint32_t a0b0 = a0*b0;
  uint32_t a1b1 = a1*b1;
  uint32_t middle = (a0 + a1)*(b0 + b1) % params.q;
  middle = mod_sub(middle, (a0b0 + a1b1) % params.q);
  a0 = (a0b0 + ((middle & 0x3fff) << 14) + (middle >> 14)*0xffff) % params.q;
  a0 = mod_sub(a0, a1b1);
  a1 = (((a1b1 >> 12)*0xffff % params.q) + ((a1b1 & 0xfff) << 16) % params.q) % params.q;
  return (a0 + a1) % params.q;
}

// mod mul for power pc
/*
uint32_t mod_mul(uint32_t a, uint32_t b) {
  uint32_t u = 0, l = 0, ans, c = 0xffff0;
  __asm__(
    "mullw %0, %1, %2\n\t" :
    "=r"(l) :
    "r"(a), "r"(b) :
  );
  __asm__(
    "mulhwu %0, %1, %2\n\t" :
    "=r"(u) :
    "r"(a), "r"(b) :
  );
  ans = l % params.q;
  __asm__(
    "mullw %0, %1, %2\n\t" :
    "=r"(l) :
    "r"(u), "r"(c) :
  );
  __asm__(
    "mulhwu %0, %1, %2\n\t" :
    "=r"(u) :
    "r"(u), "r"(c) :
  );
  ans += l % params.q;
  ans += (u * 0xffff0) % params.q;
  return ans % params.q;
}
*/

uint32_t mod_pow(uint32_t b, uint32_t e) {
  uint32_t result = 1;
  while (e > 0) {
    if((e & 0x1) == 0x1) {
      result = mod_mul(result, b);
    }
    e >>= 1;
    b = mod_mul(b, b);
  }
  return result;
}

void poly_add(uint32_t *x, uint32_t *y, uint32_t *z) {
  for (size_t i = 0; i < params.n; i++) {
    z[i] = (x[i] + y[i]) % params.q;
  }
}

void poly_sub(uint32_t *x, uint32_t *y, uint32_t *z) {
  for (size_t i = 0; i < params.n; i++) {
    z[i] = mod_sub(x[i], y[i]);
  }
}

void poly_inner_product(uint32_t *x, uint32_t *y, uint32_t *z) {
  for (size_t i = 0; i < params.n; i++) {
    z[i] = mod_mul(x[i], y[i]);
  }
}

uint32_t poly_is_equal(uint32_t *x, uint32_t *y) {
  uint32_t rv = 1;
  for (size_t i = 0; i < params.n; i++) {
    if(x[i] != y[i]) {
      rv = 0;
      break;
    }
  }
  return rv;
}

void dwt_init() {
  n_inv = mod_pow(params.n, params.q-2);
  omega = (uint32_t *)calloc(2*params.n + 1, sizeof(uint32_t));
  if(omega == NULL) {
    debug(printf("dwt_init: calloc failed.\n");)
  }

  omega[0] = 1;
  omega[1] = mod_pow(params.prim_root, (params.q-1)/(2*params.n));
  for (size_t i = 2; i < 2*params.n+1; i++) {
    omega[i] = mod_mul(omega[1], omega[i-1]);
  }
}

void dwt_finalize() {
  free(omega);
}

void dwt(uint32_t *mem) {
  for (size_t i = 0; i < params.n; i++) {
    mem[i] = mod_mul(mem[i], omega[i]);
  }
  int b = params.n;
  for (int stage = 0; stage < params.dwt_stage; stage++) {
    for (int i = 0; i < params.n/b; i++) {
      int offset = b*i;
      for (int j = 0; j < b/2; j++) {
      	uint32_t A = mem[offset + j];
        uint32_t B = mem[offset + j + b/2];
        mem[offset + j] = mod_add(A, B);
        mem[offset + j + b/2] = mod_mul(mod_sub(A, B), omega[j * 2*params.n/b]);
      }
    }
    b /= 2;
  }
}

void idwt(uint32_t *mem) {
  int b = 2;
  for (int stage = 0; stage < params.dwt_stage; stage++) {
    for (int i = 0; i < params.n/b; i++) {
      int offset = b*i;
      for (int j = 0; j < b/2; j++) {
        uint32_t A = mem[offset + j];
        uint32_t B = mod_mul(mem[offset + j + b/2], omega[2*params.n - j * 2*params.n/b]);
        mem[offset + j] = mod_add(A, B);
        mem[offset + j + b/2] = mod_sub(A, B);
      }
    }
    b *= 2;
  }
  for(int i = 0; i < params.n; i++) {
    mem[i] = mod_mul(mod_mul(mem[i], n_inv), omega[2*params.n-i]);
  }
}

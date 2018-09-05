#ifndef TESLA_H
#define TESLA_H

#include <stdint.h>

#define FMCMD_TESLA_SIGN 0x0001
#define RESERVED 0

typedef struct {
  uint32_t n;
  uint32_t q;
  float sigma;
  uint32_t omega;
  uint32_t omega_pr;
  float eta;
  uint32_t beta;
  uint32_t d;
  uint32_t B;
  uint32_t U;
  uint32_t prim_root;
  uint32_t dwt_stage;
  uint32_t public_key_length;
  uint32_t secret_key_length;
  uint32_t signature_length;
} TESLAParams;

#endif

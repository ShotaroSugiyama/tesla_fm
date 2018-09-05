#ifndef RANDOM_H
#define RANDOM_H

#include <stdlib.h>
#include <stdio.h>
#include <integers.h>
#include <cryptoki.h>
#include <cprovtbl.h>
#include <cprovpch.h>
#include <csa8hiface.h>
#include <string.h>
#include <fmsw.h>
#include <fm.h>
#include <fmdebug.h>
#include <limits.h>

void chacha20_init(uint32_t*, uint32_t*);
void chacha20_quarter_round(uint32_t*, uint32_t*, uint32_t*, uint32_t*);
void prng(uint32_t, uint32_t*, uint32_t*, uint32_t*, uint32_t);

CK_RV mod_gaussian_sampling(
  CK_SESSION_HANDLE*, float, uint32_t, uint32_t*, uint32_t
);
CK_RV mod_sampling(CK_SESSION_HANDLE*, uint32_t, uint32_t*, uint32_t);

#endif

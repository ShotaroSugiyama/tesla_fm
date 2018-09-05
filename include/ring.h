#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fmdebug.h>

#include "tesla.h"

#ifndef RING_H
#define RING_H

uint32_t mod_sub(uint32_t, uint32_t);
uint32_t mod_add(uint32_t, uint32_t);
uint32_t mod_mul(uint32_t, uint32_t);
uint32_t mod_pow(uint32_t, uint32_t);

void poly_add(uint32_t*, uint32_t*, uint32_t*);
void poly_sub(uint32_t*, uint32_t*, uint32_t*);
void poly_inner_product(uint32_t*, uint32_t*, uint32_t*);

uint32_t poly_is_equal(uint32_t*, uint32_t*);

void dwt_init();
void dwt_finalize();
void dwt(uint32_t*);
void idwt(uint32_t*);

#endif

#ifndef HASH_H
#define HASH_H

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
#include <fmciphobj.h>

#include "tesla.h"

uint32_t hash_f(uint32_t *, uint32_t *);
void d_rounding(uint32_t*);
uint32_t l_norm_inf(uint32_t*);

#endif

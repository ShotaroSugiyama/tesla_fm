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

#include "../include/tesla.h"
#include "../include/random.h"
#include "../include/ring.h"
#include "../include/hash.h"

extern CprovFnTable_t *FM_GetCprovFuncs(void);

TESLAParams params = {
  1024, //n
  268369921, //q
  139.2887752, //sigma = 164/sqrtf(2*logf(2))
  37, //omega
  51, //omega_pr
  19.30, //eta
  4, //beta
  26, //d
  67092480, //B
  16349, //U
  11, //prim_root
  10, //dwt_stage
  1024*2+8, //public_key_length
  1024*3, //secret_key_length
  1024+16 //signature_length
};

CK_RV fm_tesla_sign(
  uint8_t *message,
  uint32_t message_len,
  uint32_t *public_key,
  uint32_t *secret_key,
  uint32_t *signature
) {
  uint32_t i;

  CK_SESSION_HANDLE h_session;
  CK_RV rv;

  // Initialize DWT for polynomial multiplications
  dwt_init();

  rv = C_Initialize(NULL_PTR);
  if(rv != CKR_OK) {
    return rv;
  }

  rv = C_OpenSession(0, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &h_session);
  if(rv != CKR_OK) {
    return rv;
  }

// -----------------------------------------------------------------------------
// Allocate buffers
// -----------------------------------------------------------------------------
  uint32_t *key_t1, *key_t2, *seed;
  uint32_t *key_s, *key_e1, *key_e2;
  uint32_t *a1, *a2, *v1, *v2, *f_digest, *w1, *w2;
  uint8_t *v1_c, *v2_c;
  uint32_t *bounded_noise;
  uint32_t *sig_z, *sig_c;
  key_t1 = public_key;
  key_t2 = &public_key[params.n];
  seed = &public_key[2*params.n];
  key_s = secret_key;
  key_e1 = &secret_key[params.n];
  key_e2 = &secret_key[2*params.n];
  sig_z = signature;
  sig_c = &signature[params.n];
  a1 = (uint32_t*)calloc(params.n, sizeof(uint32_t));
  a2 = (uint32_t*)calloc(params.n, sizeof(uint32_t));
  v1 = (uint32_t*)calloc(params.n, sizeof(uint32_t));
  v2 = (uint32_t*)calloc(params.n, sizeof(uint32_t));
  w1 = (uint32_t*)calloc(params.n, sizeof(uint32_t));
  w2 = (uint32_t*)calloc(params.n, sizeof(uint32_t));
  v1_c = (uint8_t*)calloc(params.n, sizeof(uint8_t));
  v2_c = (uint8_t*)calloc(params.n, sizeof(uint8_t));
  f_digest = (uint32_t*)calloc(params.n, sizeof(uint32_t));
  bounded_noise = (uint32_t*)calloc(params.n, sizeof(uint32_t));
  if (
    a1 == NULL || a2 == NULL ||
    v1 == NULL || v2 == NULL ||
    f_digest == NULL ||
    w1 == NULL || w2 == NULL ||
    v1_c == NULL || v2_c == NULL ||
    bounded_noise == NULL
  ) {
    debug(printf("buffer calloc failed.\n");)
    return CKR_HOST_MEMORY;
  }

// -----------------------------------------------------------------------------
// Generate secret key
// -----------------------------------------------------------------------------
  rv = mod_gaussian_sampling(
    &h_session,
    params.sigma,
    params.secret_key_length,
    secret_key,
    params.q
  );
  if(rv != CKR_OK) {
    return rv;
  }
  dwt(key_s);
  dwt(key_e1);
  dwt(key_e2);

// -----------------------------------------------------------------------------
// Generate public key
// -----------------------------------------------------------------------------
  rv = mod_sampling(&h_session, 8, seed, 0);
  if(rv != CKR_OK) {
    return rv;
  }
  prng(params.n, a1, a2, seed, params.q);
  dwt(a1);
  dwt(a2);
  poly_inner_product(a1, key_s, key_t1);
  poly_inner_product(a2, key_s, key_t2);
  poly_add(key_t1, key_e1, key_t1);
  poly_add(key_t2, key_e2, key_t2);

// -----------------------------------------------------------------------------
// Signing
// -----------------------------------------------------------------------------
  CK_MECHANISM mech = {CKM_SHA512, NULL_PTR, 0};
  CK_ULONG digest_len = 64;
  uint8_t hash[64];

  int max_count = 0;
  while(1) {
    max_count++;
    if(max_count == 10000) {
      return 0x250;
    }

    // sample r
    mod_sampling(&h_session, params.n, bounded_noise, 2*params.B+1);
    for (i = 0; i < params.n; i++) {
      bounded_noise[i] = mod_sub(bounded_noise[i], params.B);
    }
    dwt(bounded_noise);

    // calc v1 and v2 (assigned in w1 and w2)
    poly_inner_product(a1, bounded_noise, w1);
    poly_inner_product(a2, bounded_noise, w2);
    memcpy(v1, w1, sizeof(uint32_t)*params.n);
    memcpy(v2, w2, sizeof(uint32_t)*params.n);

    idwt(v1);
    idwt(v2);
    d_rounding(v1);
    d_rounding(v2);
    for (i = 0; i < params.n; i++) {
      v1_c[i] = v1[i];
      v2_c[i] = v2[i];
    }

    C_DigestInit(h_session, &mech);
    rv = C_DigestUpdate(h_session, v1_c, params.n);
    if(rv != CKR_OK) {
      return rv;
    }
    rv = C_DigestUpdate(h_session, v2_c, params.n);
    if(rv != CKR_OK) {
      return rv;
    }
    rv = C_DigestUpdate(h_session, message, message_len);
    if(rv != CKR_OK) {
      return rv;
    }
    rv = C_DigestFinal(h_session, hash, &digest_len);
    if(rv != CKR_OK) {
      return digest_len;
      return rv;
    }
    for (i = 0; i < 16; i++) {
      sig_c[i] =
      ((uint32_t)hash[4*i] << 24) +
      ((uint32_t)hash[4*i+1] << 16) +
      ((uint32_t)hash[4*i+2] << 8) +
      (uint32_t)hash[4*i+3];
    }

    if(hash_f(sig_c, f_digest) != 0) {
      continue;
    }

    dwt(f_digest);
    poly_inner_product(key_s, f_digest, sig_z);
    poly_add(sig_z, bounded_noise, sig_z);
    idwt(sig_z);
    if(l_norm_inf(sig_z) > (params.B - params.U)) {
      continue;
    }

    // use r (bounded_noise) for buf
    poly_inner_product(key_e1, f_digest, bounded_noise);
    poly_sub(w1, bounded_noise, w1);
    poly_inner_product(key_e2, f_digest, bounded_noise);
    poly_sub(w2, bounded_noise, w2);

    idwt(w1);
    idwt(w2);
    d_rounding(w1);
    d_rounding(w2);

    if(poly_is_equal(v1, w1) && poly_is_equal(v2, w2)) {
      idwt(key_s);
      idwt(key_e1);
      idwt(key_e2);
      idwt(key_t1);
      idwt(key_t2);
      break;
    }
  }

  rv = C_CloseSession(h_session);
  if(rv != CKR_OK) {
    return rv;
  }

  rv = C_Finalize(NULL_PTR);

// -----------------------------------------------------------------------------
// Free buffers
// -----------------------------------------------------------------------------
  dwt_finalize();
  free(a1);
  free(a2);
  free(v1);
  free(v2);
  free(w1);
  free(w2);
  free(v1_c);
  free(v2_c);
  free(bounded_noise);
  free(f_digest);

  return rv;
}

/* command handler entry point */
static void fm_tesla_sign_handler(HI_MsgHandle token, void *request_buf, uint32_t request_len) {
  CK_RV rv;
  uint32_t i;

  /* Argument sanity check */
  if(request_len < sizeof(uint8_t)) {
    debug(printf("Argument sanity check failed.\n");)
    return;
  }

  /* parse command */
  uint16_t cmd = (uint16_t)ntoh_short(*(uint16_t*)request_buf);

  /* Allocate reply buf */
  uint32_t out_len_user = SVC_GetUserReplyBufLen(token);
  uint8_t *out = SVC_GetReplyBuffer(token, out_len_user);

  /* command switch, only one command */
  if(cmd == FMCMD_TESLA_SIGN) {
    uint32_t key_length = params.public_key_length + params.secret_key_length;
    uint32_t signature_length = params.signature_length;
    rv = fm_tesla_sign(
      (uint8_t *)request_buf + 2,
      request_len-2,
      (uint32_t *)out,
      (uint32_t *)(out + sizeof(uint32_t)*(params.public_key_length)),
      (uint32_t *)(out + sizeof(uint32_t)*(key_length))
    );
    for (i = 0; i < key_length + signature_length; i++) {
      *(uint32_t *)(out+sizeof(uint32_t)*i) = hton_long(*(uint32_t *)(out+sizeof(uint32_t)*i));
    }
    SVC_SendReply(token, (uint32_t)rv);
  }
  else {
    SVC_SendReply(token, (uint32_t)CKR_FUNCTION_NOT_SUPPORTED);
  }
}

/* FM Startup function */
FM_RV Startup(void) {
  /* register handler for our new API */
  debug(printf("Registering dispatch function ... ");)
  FM_RV rv = FMSW_RegisterDispatch(FM_NUMBER_CUSTOM_FM, fm_tesla_sign_handler);
  debug(printf("registered. Return Code = 0x%x", rv);)
  return rv;
}

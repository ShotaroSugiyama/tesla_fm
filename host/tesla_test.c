#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fmerr.h>
#include <cryptoki.h>
#include <md.h>
#include <integers.h>
#include <csa8fm.h>
#include <endyn.h>

#include "../include/tesla.h"

TESLAParams params = {
  1024,
  268369921,
  //164/sqrtf(2*logf(2)),
  139.2887752,
  37,
  51,
  19.30,
  4,
  26,
  67092480,
  16349,
  11,
  10,
  1024*2+8,
  1024*3,
  1024+16
};

uint32_t tesla_sign(
  uint8_t *message,
  uint32_t message_len,
  uint32_t *public_key,
  uint32_t *secret_key,
  uint32_t *signature
) {

  MD_Buffer_t request[3], reply[4];

  uint16_t cmd = hton_short(FMCMD_TESLA_SIGN);
  request[0].pData = (uint8_t*)&cmd;
  request[0].length = sizeof(uint16_t);

  request[1].pData = message;
  request[1].length = message_len;

  /** The last MD_Buffer_t MUST be terminated in this fashion. - VERY IMPORTANT */
  request[2].pData = NULL;
  request[2].length = 0;

  reply[0].pData = (uint8_t*)public_key;
  reply[0].length = sizeof(uint32_t)*(params.public_key_length);
  reply[1].pData = (uint8_t*)secret_key;
  reply[1].length = sizeof(uint32_t)*(params.secret_key_length);
  reply[2].pData  = (uint8_t*)signature;
  reply[2].length = sizeof(uint32_t)*(params.signature_length);

  /** Terminate our receive buffer as per earlier comment - VERY IMPORTANT */
  reply[3].pData = NULL;
  reply[3].length = 0;

  uint32_t app_state = MDR_UNSUCCESSFUL, recv_len = 0, originator_id = 0;
  uint8 adapter = 0;
  MD_SendReceive(
    adapter,
    originator_id,
    FM_NUMBER_CUSTOM_FM,
    request,
    RESERVED,
    reply,
    &recv_len,
    &app_state
  );

  int i;
  for (i = 0; i < params.public_key_length; i++) {
    public_key[i] = ntoh_long(public_key[i]);
  }
  for (i = 0; i < params.secret_key_length; i++) {
    secret_key[i] = ntoh_long(secret_key[i]);
  }
  for (i = 0; i < params.signature_length; i++) {
    signature[i] = ntoh_long(signature[i]);
  }

  return app_state;
}

int main() {

  MD_RV rv = MDR_UNSUCCESSFUL;

  /** Initialize the message dispatch library */
  rv = MD_Initialize();
  if(rv != MDR_OK) {
      fprintf(stderr, "MD_Initialize %x\n", rv);
      exit(EXIT_FAILURE);
  }

  uint8_t message[8] = "message";
  uint32_t message_len = 8;
  uint32_t public_key[params.public_key_length];
  uint32_t secret_key[params.secret_key_length];
  uint32_t signature[params.signature_length];

	rv = tesla_sign(message, message_len, public_key, secret_key, signature);

  if(rv != MDR_OK) {
      fprintf(stderr, "tesla_sign failed with error code: 0x%x\n", rv);
      exit(EXIT_FAILURE);
  }

  /** Finalize the library. */
  MD_Finalize();

  int i;
  printf("module TestVector\nKey = {\"t1\":[");
  for (i = 0; i < params.n-1; i++) {
    printf("%u, ", public_key[i]);
  }
  printf("%u], ", public_key[params.n-1]);
  printf("\"t2\":[");
  for (i = 0; i < params.n-1; i++) {
    printf("%u, ", public_key[i+params.n]);
  }
  printf("%u], ", public_key[2*params.n-1]);
  printf("\"seed\":[");
  for (i = 0; i < 7; i++) {
    printf("%u, ", public_key[i+2*params.n]);
  }
  printf("%u], ", public_key[7+2*params.n]);

  printf("\"s\":[");
  for (i = 0; i < params.n-1; i++) {
    printf("%u, ", secret_key[i]);
  }
  printf("%u], ", secret_key[params.n-1]);
  printf("\"e1\":[");
  for (i = 0; i < params.n-1; i++) {
    printf("%u, ", secret_key[i+params.n]);
  }
  printf("%u], ", secret_key[2*params.n-1]);
  printf("\"e2\":[");
  for (i = 0; i < params.n-1; i++) {
    printf("%u, ", secret_key[i+2*params.n]);
  }
  printf("%u]}\n", secret_key[3*params.n-1]);

  printf("Signature = {\"z\":[");
  for (i = 0; i < params.n-1; i++) {
    printf("%u, ", signature[i]);
  }
  printf("%u], ", signature[params.n-1]);
  printf("\"c\":[");
  for (i = 0; i < 15; i++) {
    printf("%u, ", signature[i+params.n]);
  }
  printf("%u]}\nend\n", signature[15+params.n]);

  exit(EXIT_SUCCESS);
}

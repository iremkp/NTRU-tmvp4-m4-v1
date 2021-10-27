#include "api.h"
#include "randombytes.h"
#include "hal.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "poly.h"
#include "owcpa.h"
#define MAX_SIZE 0x16000

extern void mul_509(uint16_t *res_coeffs, const uint16_t *small_coeffs, const uint16_t *big_coeffs);

uint16_t x[NTRU_N];
uint16_t y[NTRU_N];
uint16_t z[NTRU_N];
uint16_t check[NTRU_N * 2 - 1];

static void send_stack_usage(const char *s, unsigned int c) {
  char outs[120];
  send_USART_str(s);
  sprintf(outs, "%u\n", c);
  send_USART_str(outs);
}


unsigned int canary_size = MAX_SIZE;
volatile unsigned char *p;
unsigned int c;
uint8_t canary = 0x42;

unsigned char key_a[CRYPTO_BYTES], key_b[CRYPTO_BYTES];
unsigned char pk[CRYPTO_PUBLICKEYBYTES];
unsigned char sendb[CRYPTO_CIPHERTEXTBYTES];
unsigned char sk_a[CRYPTO_SECRETKEYBYTES];
unsigned char sk[CRYPTO_SECRETKEYBYTES];
unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
unsigned int stack_key_gen, stack_encaps, stack_decaps, stack_key_gen_cpa, stack_enc_cpa, stack_dec_cpa, stack_tmvp_polymul, stack_ntt_polymul, stack_toom_polymul;

#define FILL_STACK()                                                           \
  p = &a;                                                                      \
  while (p > &a - canary_size)                                                 \
    *(p--) = canary;
#define CHECK_STACK()                                                          \
  c = canary_size;                                                             \
  p = &a - canary_size + 1;                                                    \
  while (*p == canary && p < &a) {                                             \
    p++;                                                                       \
    c--;                                                                       \
  }                                                                            

static int test_keys(void) {
  volatile unsigned char a;
  // Key-pair generation
  FILL_STACK()
  crypto_kem_keypair(pk, sk_a);
  CHECK_STACK()
  if(c >= canary_size) return -1; 
  stack_key_gen = c;

  // Encapsulation
  FILL_STACK()
  crypto_kem_enc(sendb, key_b, pk);
  CHECK_STACK()
  if(c >= canary_size) return -1; 
  stack_encaps = c;

  // Decapsulation
  FILL_STACK()
  crypto_kem_dec(key_a, sendb, sk_a);
  CHECK_STACK()
  if(c >= canary_size) return -1; 
  stack_decaps = c;
  
  //#ifdef NTRU
  unsigned char seed[NTRU_SEEDBYTES];
  randombytes(seed, sizeof seed);
  
    // Alice generates a public key
  FILL_STACK()
  owcpa_keypair(pk, sk, seed);
  CHECK_STACK()
  if(c >= canary_size) return -1; 
  stack_key_gen_cpa = c;

  uint8_t rm1[NTRU_OWCPA_MSGBYTES];
  uint8_t rm_seed[NTRU_SAMPLE_RM_BYTES];
  
  randombytes(rm_seed, NTRU_SAMPLE_RM_BYTES);
  owcpa_samplemsg(rm1, rm_seed);

  // Bob derives a secret key and creates a response
  FILL_STACK()
  owcpa_enc(ct, rm1, pk);
  CHECK_STACK()
  if(c >= canary_size) return -1; 
  stack_enc_cpa= c;
  
  uint8_t rm2[NTRU_OWCPA_MSGBYTES];

  // Alice uses Bobs response to get her secret key
  FILL_STACK()
  owcpa_dec(rm2, ct, sk);
  CHECK_STACK()
  if(c >= canary_size) return -1; 
  stack_dec_cpa = c;
 
  
  
  
  #ifdef TOOM
  FILL_STACK()
  polymul_asm(z, x, y);
  CHECK_STACK()
  if(c >= canary_size) return -1; 
  stack_toom_polymul = c;
  #elif defined NTT
  FILL_STACK()
  //mul_509(z, x, y);
  //Good_mul_768(z, x, y);
  //mixed_radix_NTT_mul_864(z, x, y);
  //polymul_asm(z, x, y);
  poly_SignedZ3_Rq_mul(z, x, y);
  CHECK_STACK()
  if(c >= canary_size) return -1; 
  stack_ntt_polymul = c;
  #else
  FILL_STACK()  
 asm_polymul_701_704(z, x, y);
  CHECK_STACK()
  if(c >= canary_size) return -1; 
  stack_tmvp_polymul = c;
  #endif
   //#endif
  if (memcmp(key_a, key_b, CRYPTO_BYTES)){
    return -1;
  } else {    
    send_stack_usage("cca key gen stack usage", stack_key_gen);
    send_stack_usage("encapsulation stack usage", stack_encaps);
    send_stack_usage("decapsulation stack usage", stack_decaps);
	send_stack_usage("cpa key gen stack usage", stack_key_gen_cpa);
    send_stack_usage("encryption stack usage", stack_enc_cpa);
    send_stack_usage("decryption cpa stack usage", stack_dec_cpa);
	#ifdef TMVP
	send_stack_usage("tmvp polymul stack usage:", stack_tmvp_polymul);
	#elif defined NTT
	send_stack_usage("ntt polymul stack usage:", stack_ntt_polymul);
	#else
	send_stack_usage("toom polymul stack usage:", stack_toom_polymul);
  #endif
    send_USART_str("OK KEYS\n");
    return 0;
  }
}

int main(void) {
  clock_setup(CLOCK_FAST);
  gpio_setup();
  usart_setup(115200);
  rng_enable();

  // marker for automated benchmarks
  send_USART_str("==========================");
  canary_size = MAX_SIZE;
  while(test_keys()){
    canary_size -= 0x1000;
    if(canary_size == 0) {
      send_USART_str("failed to measure stack usage.\n");
      break;
    }
  }
  // marker for automated benchmarks
  send_USART_str("#");

  while (1);

  return 0;
}

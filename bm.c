/**
 * bm.c - Benchmarking and compliance. Last modified 29 Dec 2014. 
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdio.h>
#include "aez.h"

#define HZ (2.9e9) /* CPU speed of host sytem. */ 
#define TRIALS 100000

void display_block(const Block X)
{
  for (int i = 0; i < 4; i ++)
    printf("0x%08x ", X.word[i]); 
}

void display_context(Context *context)
{
  unsigned i; 
  printf("+---------------------------------------------------+\n"); 
  printf("| I   = "); display_block(context->K[0]);  printf("|\n"); 
  printf("| J   = "); display_block(context->K[2]);  printf("|\n"); 
  printf("d| L   = "); display_block(context->K[1]);  printf("|\n"); 
  printf("| L'  = "); display_block(context->L1); printf("|\n"); 

  for (i = 0; i < 9; i++)
  {
    printf("| %d*J = ", i); 
    display_block(context->Js[i]); 
    printf("|\n"); 
  }

  printf("+---------------------------------------------------+\n"); 
}


void benchmark() {

  static const int msg_len [] = {64,    128,   256,   512, 
                                 1024,  4096,  10000, 100000,
                                 1<<18, 1<<20, 1<<22 }; 
  static const int num_msg_lens = 7; 
  unsigned i, j, auth_bytes = 16, key_bytes = 16; 
  
  Context context; 
  ALIGN(16) Block key;   memset(key.byte, 0, 16); 
  ALIGN(16) Block nonce; memset(nonce.byte, 0, 16); 
  aez_extract(&context, key.byte, key_bytes);

  Byte *message = malloc(auth_bytes + msg_len[num_msg_lens-1]); 
  Byte *ciphertext = malloc(auth_bytes + msg_len[num_msg_lens-1]); 
  Byte *plaintext = malloc(auth_bytes + msg_len[num_msg_lens-1]); 

  clock_t t; 
  double total_cycles; 
  double total_bytes; 

  for (i = 0; i < num_msg_lens; i++)
  {
    t = clock(); 
    for (j = 0; j < TRIALS; j++)
    {
      aez_encrypt(ciphertext, message, msg_len[i], nonce.byte, 16, 
          0, NULL, 0, auth_bytes, &context); 
      nonce.word[0] ++; 
    }
    t = clock() - t; 
    total_cycles = t * HZ / CLOCKS_PER_SEC; 
    total_bytes = (double)TRIALS * msg_len[i]; 
    printf("%8d bytes, %.2f cycles per byte\n", msg_len[i], 
                               total_cycles/total_bytes); 
  }
  
  //ciphertext[343] = 'o';
  nonce.word[0] --; i --; 
  if (aez_decrypt(plaintext, ciphertext, msg_len[i] + auth_bytes, nonce.byte, 16,
               0, NULL, 0, auth_bytes, &context) != INVALID)
    printf("Success! ");
  else 
    printf("Tag mismatch. ");
  printf("\n"); 

  free(message); 
  free(ciphertext); 
  free(plaintext); 
}

  
void verify() 
{
  Byte  key [] = "One day we will.", nonce [] = "Things are occuring!"; 
  
  Block sum; zero_block(sum); 

  unsigned key_bytes = strlen((const char *)key), 
           nonce_bytes = strlen((const char *)nonce), 
           auth_bytes = 16, i, res, msg_len = 1024; 

  Byte *message = malloc(auth_bytes + msg_len); 
  Byte *ciphertext = malloc(auth_bytes + msg_len); 
  Byte *plaintext = malloc(auth_bytes + msg_len); 
  memset(ciphertext, 0, msg_len + auth_bytes); 
  memset(plaintext, 0, msg_len + auth_bytes); 
  memset(message, 0, msg_len + auth_bytes);
  
  Context context; 
  aez_extract(&context, key, key_bytes); 
  //display_context(&context); 
  for (i = 0; i < msg_len; i++)
  {
    aez_encrypt(ciphertext, message, i, nonce, nonce_bytes, 
          NULL, NULL, 0, auth_bytes, &context); 
   
    xor_bytes(sum.byte, sum.byte, ciphertext, 16); 
  
    res = aez_decrypt(plaintext, ciphertext, i + auth_bytes, nonce, nonce_bytes, 
           NULL, NULL, 0, auth_bytes, &context); 

    if (res == INVALID)
      printf("invalid\n");

    if (memcmp(plaintext, message, i) != 0)
      printf("msg length %d: plaintext mismatch!\n", i + auth_bytes); 
  }
  display_block(sum); printf("\n");
  free(message); 
  free(ciphertext); 
  free(plaintext); 
}

int main()
{
  verify(); 
  benchmark(); 
  return 0; 
}

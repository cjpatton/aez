/**
 * aez.c -- AEZv3, a Caesar submission proposed by Viet Tung Hoang, Ted Krovetz,
 * and Phillip Rogaway. This implementation is deesigned to be as fast as 
 * possible on the target architecture. 
 *
 * It uses a platform-independent implementation of AES (by Vincent Rijmen 
 * et al.) if the x86 AES-NI instruction set is unavailable (see 
 * rijndael-alg-fst.{h,c}). This code is unmodified, exceppt that the flag 
 * `INTERMEDIATE_VALUE_KAT` is set. 
 *
 *   Written by Chris Patton <chrispatton@gmail.com>.
 *
 * This program is dedicated to the public domain. 
 *
 * Compile with "-Wall -O3 -std=c99 aez.c rijndael-alg-fst.c". The usual AES-NI 
 * flags are "-maes -mssse3".  
 */

#include <assert.h>

/*
 * Architecture flags. If the platform supports the AES-NI and SSSE3 instruction 
 * sets, set __USE_AES_NI; if the platform doesn't have hardware support for AES, 
 * but is a 64-bit architecture, then set __ARCH_64; if the system is 32-bit, un-
 * set both __USE_AES_NI and __ARCH_64. 
 */
#define __USE_AES_NI
#define __ARCH_64



#ifndef __USE_AES_NI 
#include "rijndael-alg-fst.h"
#else 
#include <wmmintrin.h>
#include <tmmintrin.h>
#endif 

#define INVALID -1 /* Reject plaintext (inauthentic). */ 

/* AES input/output/keys are block aligned in order to support AES-NI. */ 
#define ALIGN(n) __attribute__ ((aligned(n))) 

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


/* ----- AEZ context. -------------------------------------------------------*/

typedef uint8_t Byte; 
typedef uint32_t Word; 
typedef uint64_t Long; 

typedef union {
  ALIGN(16) Byte byte  [16]; /* Byte addressing needed for a few operations. */ 
  ALIGN(16) Word word  [4];  /* 32-bit systems. */ 
  ALIGN(16) Long lword [2];  /* 64-bit systems. */ 
#ifdef __USE_AES_NI
  __m128i block; 
#endif
} Block; 

typedef struct {

  /* Key schedules for software AES code. There is probably a way to 
   * do this without explicitly laying out each key schedule. */ 
#ifndef __USE_AES_NI
  Block k0[5], k1[5], k2[5], K[11];
#endif

  /* Tweaks, key. */
  Block I, L, L1, J, Js [9]; 

} Context; 

static void display_block(const Block X)
{
  for (int i = 0; i < 4; i ++)
    printf("0x%08x ", X.word[i]); 
}


/* ---- Various primitives. ------------------------------------------------ */

#define max(a, b) (a < b ? b : a)

/* Reverse bytes of a 32-bit integer. */ 
#define reverse_u32(n) ( \
 (((n) & 0x000000ffu) << 24) | \
 (((n) & 0x0000ff00u) <<  8) | \
 (((n) & 0x00ff0000u) >>  8) | \
 (((n) & 0xff000000u) >> 24)   \
)

/*
 * rinjdael-alg-fst.{h,c} requires key words in big endian byte order. 
 * toggle_endian() operates on 128-bit blocks. AES-NI doesn't have this
 * layout. 
 */
#ifndef __USE_AES_NI 
  #define toggle_endian(X) { \
    (X).word[0] = reverse_u32((X).word[0]); \
    (X).word[1] = reverse_u32((X).word[1]); \
    (X).word[2] = reverse_u32((X).word[2]); \
    (X).word[3] = reverse_u32((X).word[3]); \
  }
#else 
  #define toggle_endian(X) { \
  }
#endif 

#ifdef __USE_AES_NI /* Copy a block. */ 
  #define cp_block(X, Y) { \
    (X).block = (Y).block; \
  }
#else 
  #ifdef __ARCH_64 
    #define cp_block(X, Y) { \
     (X).lword[0] = (Y).lword[0]; \
     (X).lword[1] = (Y).lword[1]; \
   }
  #else
    #define cp_block(X, Y) { \
     (X).word[0] = (Y).word[0]; \
     (X).word[1] = (Y).word[1]; \
     (X).word[2] = (Y).word[2]; \
     (X).word[3] = (Y).word[3]; \
  }
  #endif 
#endif 

#ifdef __USE_AES_NI /* Set block to zero. */ 
  #define zero_block(X) { \
    (X).block = _mm_setzero_si128(); \
  }
#else 
  #ifdef __ARCH_64 
    #define zero_block(X) { \
      (X).lword[0] = 0; \
      (X).lword[1] = 0; \
    }
  #else 
    #define zero_block(X) { \
      (X).word[0] = 0; \
      (X).word[1] = 0; \
      (X).word[2] = 0; \
      (X).word[3] = 0; \
    }
  #endif
#endif 

#ifdef __USE_AES_NI /* XOR blocks. */ 
  #define xor_block(X, Y, Z) { \
    (X).block = (Y).block ^ (Z).block; \
  }
#else
  #ifdef __ARCH_64
    #define xor_block(X, Y, Z) { \
      (X).lword[0] = (Y).lword[0] ^ (Z).lword[0]; \
      (X).lword[1] = (Y).lword[1] ^ (Z).lword[1]; \
    }
  #else 
    #define xor_block(X, Y, Z) { \
      (X).word[0] = (Y).word[0] ^ (Z).word[0]; \
      (X).word[1] = (Y).word[1] ^ (Z).word[1]; \
      (X).word[2] = (Y).word[2] ^ (Z).word[2]; \
      (X).word[3] = (Y).word[3] ^ (Z).word[3]; \
    }
  #endif 
#endif

#ifdef __USE_AES_NI
  #define load_block(dst, src) { \
    dst.block = _mm_loadu_si128((__m128i *)src); \
  }
  #define store_block(dst, src) { \
    _mm_storeu_si128((__m128i*)dst, ((Block)src).block); \
  }
#else 
  #define load_block(dst, src) memcpy(dst.byte, (Byte *)src, 16) 
  #define store_block(dst, src) memcpy((Byte *)dst, ((Block)src).byte, 16) 
#endif 

/* Copy a partial block. */ 
#define cp_bytes(dst, src, n) memcpy((Byte *)dst, (Byte *)src, n) 

/* XOR a partial block. */
static void xor_bytes(Byte X [], const Byte Y [], const Byte Z [], unsigned n)
{
  for (int i = 0; i < n; i++)
    X[i] = Y[i] ^ Z[i]; 
}


/* ----- AES calls. -------------------------------------------------------- */


/* AES10. */ 
void aes10(Block *Y, Block X, Context *context) 
{
#ifdef __USE_AES_NI
  X.block = _mm_aesenc_si128(X.block, context->I.block);
  X.block = _mm_aesenc_si128(X.block, context->L.block);
  X.block = _mm_aesenc_si128(X.block, context->J.block);
  X.block = _mm_aesenc_si128(X.block, context->I.block);
  X.block = _mm_aesenc_si128(X.block, context->L.block);
  X.block = _mm_aesenc_si128(X.block, context->J.block);
  X.block = _mm_aesenc_si128(X.block, context->I.block);
  X.block = _mm_aesenc_si128(X.block, context->L.block);
  X.block = _mm_aesenc_si128(X.block, context->J.block);
  Y->block = _mm_aesenc_si128(X.block, context->I.block);
#else
  cp_block(*Y, X); 
  rijndaelEncryptRound((uint32_t *)context->K, 11, Y->byte, 10); 
#endif
} 

/*  AES4. */ 
void aes4_0(Block *Y, Block X, Context *context) 
{
#ifdef __USE_AES_NI
  X.block = _mm_aesenc_si128(X.block, context->I.block);
  X.block = _mm_aesenc_si128(X.block, context->J.block); 
  X.block = _mm_aesenc_si128(X.block, context->L.block); 
  Y->block = _mm_aesenc_si128(X.block, _mm_setzero_si128());
#else
  cp_block(*Y, X); 
  rijndaelEncryptRound((uint32_t *)context->k0, 10, Y->byte, 4);  
#endif

} 

void aes4_1(Block *Y, Block X, Context *context) 
{
#ifdef __USE_AES_NI
  X.block = _mm_aesenc_si128(X.block, context->J.block);
  X.block = _mm_aesenc_si128(X.block, context->L.block); 
  X.block = _mm_aesenc_si128(X.block, context->I.block); 
  Y->block = _mm_aesenc_si128(X.block, _mm_setzero_si128());
#else
  cp_block(*Y, X); 
  rijndaelEncryptRound((uint32_t *)context->k1, 10, Y->byte, 4);  
#endif
} 

void aes4_2(Block *Y, Block X, Context *context) 
{
#ifdef __USE_AES_NI
  X.block = _mm_aesenc_si128(X.block, context->L.block); 
  X.block = _mm_aesenc_si128(X.block, context->I.block); 
  X.block = _mm_aesenc_si128(X.block, context->J.block); 
  Y->block = _mm_aesenc_si128(X.block, context->I.block); 
#else
  cp_block(*Y, X); 
  rijndaelEncryptRound((uint32_t *)context->k2, 10, Y->byte, 4);  
#endif
} 

void aes4_short(Block *Y, Block X, const Block K) 
{
#ifdef __USE_AES_NI
  X.block = _mm_aesenc_si128(X.block ^ K.block, K.block); 
  X.block = _mm_aesenc_si128(X.block, K.block); 
  X.block = _mm_aesenc_si128(X.block, K.block);
  Y->block = _mm_aesenc_si128(X.block, K.block);
#else
  Block sched [5]; 
  for (int i = 0; i < 5; i++)
    cp_block(sched[i], K); 
  cp_block(*Y, X); 
  rijndaelEncryptRound((uint32_t *)sched, 10, Y->byte, 4);  
#endif
} 



/* ---- AEZ tweaks. -------------------------------------------------------- */

/*
 * Multiply-by-two operation for key tweaking. 
 */
static void dot2(Byte X []) {
  Byte tmp = X[0];
  for (int i = 0; i < 15; i++)
    X[i] = (Byte)((X[i] << 1) | (X[i+1] >> 7));
  X[15] = (Byte)((X[15] << 1) ^ ((tmp >> 7) * 135));
}

/*
 * Incremental tweak generation. Used to precompute multiples of the tweaks. 
 */
static void dot_inc(Block *Xs, int n)
{
  if (n == 0) 
    ;
  
  else if (n == 1)
    ; 

  else if (n == 2)
  {
    cp_block(Xs[2], Xs[1]);
    dot2(Xs[2].byte);
  }

  else if (n & 1) // odd
  {
    cp_block(Xs[n], Xs[n-1]); 
    xor_block(Xs[n], Xs[n], Xs[1]);    
  }

  else // even
  {
    cp_block(Xs[n], Xs[n/2]);
    dot2(Xs[n].byte); 
  }
}

/*
 * Update doubling tweak `T` if necessary. `i` doesn't actually
 * have an affect on the tweak. 
 */
static void update(Context *context, int inc_l) 
{
  if (inc_l) 
    dot2(context->L1.byte); 
}

/*
 * Reset tweak. 
 */
static void reset(Context *context)
{
  cp_block(context->L1, context->L);
  toggle_endian(context->L1); 
}



/* ----- AEZ Extract. ------------------------------------------------------ */

void extract(Context *context, const Byte *key, unsigned key_bytes)
{
  unsigned i, j, k, m;

  Block z;
  for (i = 0; i < 16; i++)
    z.byte[i] = i;
  toggle_endian(z);
  
  /* Number of blocks. */
  m = key_bytes / 16; 
  if (key_bytes % 16 > 0) m++; 
  m = max(m, 1); 

  Block C, X [3], buff, K;
  zero_block(buff); 
  zero_block(X[0]); 
  zero_block(X[1]); 
  zero_block(X[2]); 

  k = 0;
  for (j = 0; j < m-1; j++) // Full key blocks
  {
    load_block(K, &key[k]); k += 16;
    buff.word[3] = reverse_u32(j + 1); 

    for (i = 0; i < 3; i++)
    {
      buff.word[1] = reverse_u32(i + 1); 
      aes4_short(&C, buff, z); 
      toggle_endian(C);
      aes4_short(&C, K, C); 
      xor_block(X[i], X[i], C); 
    }
  }

  j = key_bytes % 16; 
  if (j > 0) // Partial last block
  {
     zero_block(K); 
     cp_bytes(K.byte, &key[k], j); 
     K.byte[j] = 0x80;
     zero_block(buff);
  }

  else // Full last block
  {
    load_block(K, &key[k]);
    buff.word[3] = reverse_u32(m);
  } 

  for (i = 0; i < 3; i++)
  {
    buff.word[1] = reverse_u32(i + 1); 
    aes4_short(&C, buff, z); 
    toggle_endian(C);
    aes4_short(&C, K, C); 
    xor_block(X[i], X[i], C);  
  }

  /* Set up key schedule and tweak context. */
  cp_block(context->I, X[0]); toggle_endian(context->I); 
  cp_block(context->J, X[1]); toggle_endian(context->J); 
  cp_block(context->L, X[2]); toggle_endian(context->L);

  /* Preompute j*J's. */
  zero_block(context->Js[0]); 
  cp_block(context->Js[1], X[1]);
  for (i = 0; i < 9; i++)
    dot_inc(context->Js, i); 
  
  /* Doubling tweak. */
  cp_block(context->L1, X[2]); 

#ifndef __USE_AES_NI
  zero_block(context->k0[0]); zero_block(context->k0[4]); 
  zero_block(context->k1[0]); zero_block(context->k1[4]); 
  zero_block(context->k2[0]); zero_block(context->K[0]); 

  cp_block(context->k0[2], context->J); cp_block(context->k1[1], context->J); 
  cp_block(context->k2[3], context->J); cp_block(context->K[3], context->J);
  cp_block(context->K[6], context->J);  cp_block(context->K[9], context->J);

  cp_block(context->k0[1], context->I); cp_block(context->k1[3], context->I); 
  cp_block(context->k2[2], context->I); cp_block(context->k2[4], context->I); 
  cp_block(context->K[1], context->I);  cp_block(context->K[4], context->I);
  cp_block(context->K[7], context->I);  cp_block(context->K[10], context->I);

  cp_block(context->k0[3], context->L); cp_block(context->k1[2], context->L); 
  cp_block(context->k2[1], context->L); cp_block(context->K[2], context->L);
  cp_block(context->K[5], context->L);  cp_block(context->K[8], context->L);
#endif

} // extract()


/* ---- AEZ Tweakable blockcipher. ----------------------------------------- */

void E(Block *Y, const Block X, int i, int j, Context *context)
{
  if (i == -1 && 0 <= j && j <= 7)
  {
    xor_block(*Y, X, context->Js[j]);
    aes10(Y, *Y, context); 
  }

  else if (i == 0 && 0 <= j && j <= 7)
  {
    xor_block(*Y, X, context->Js[j]);
    aes4_0(Y, *Y, context); 
  }

  else if (1 <= i && i <= 2 && j >= 1)
  {
    xor_block(*Y, X, context->Js[j % 8]);
    xor_block(*Y, *Y, context->L1);
    if (i == 1) aes4_1(Y, *Y, context); 
    else        aes4_2(Y, *Y, context); 
  }

  else if (i >= 3 && j >= 1)
  {
    /* The J-tweak is mixed in hash(). */ 
    xor_block(*Y, X, context->Js[j % 8]); 
    xor_block(*Y, *Y, context->L1);
    aes4_0(Y, *Y, context); 
  }

  else if (i >= 3 && j == 0)
  { 
    /* The J-tweak is mixed in hash(). */ 
    aes4_0(Y, *Y, context); 
  }

  else { printf("Uh Oh!!!\n"); assert(0); }

} // E()



/* ----- AEZ axu-hash, pseudorandom funcion. ------------------------------- */

void hash(Byte *delta, Byte *tags [], 
                unsigned num_tags, unsigned tag_bytes [],  Context *context)
{
  unsigned i, j, k, m; 
  Block H, X; 
  zero_block(H);

  Block *offset = (Block *)malloc(sizeof(Block) * (num_tags + 2)); 
  zero_block(offset[0]); cp_block(offset[1], context->Js[8]);  

  for (i = 0; i < num_tags; i++)
  {
    dot_inc(offset, i+2); 
    m = tag_bytes[i] / 16; 
    if (tag_bytes[i] % 16 > 0) m++; 
    m = max(m, 1); 
    
    k = 0; 
    for (j = 1; j < m; j++)
    {
      load_block(X, &tags[i][k]); k += 16;
      xor_block(X, X, offset[i+1]); 
      E(&X, X, 3+i, j, context);
      xor_block(H, H, X); 
      update(context, j % 8 == 0);  
    } // Full blocks
    
    j = tag_bytes[i] % 16; 
    if (j > 0) { // Partial last block
       zero_block(X); 
       cp_bytes(X.byte, &tags[i][k], j); 
       X.byte[j] = 0x80;
       j = 0; 
    }
    else { // Full last block
      load_block(X, &tags[i][k]);
      j = m; 
    }
    
    xor_block(X, X, offset[i+1]); 
    E(&X, X, 3+i, j, context); 
    xor_block(H, H, X); 
    reset(context); 
  } // Each tag
  
  free(offset); 
  cp_bytes(delta, H.byte, 16);
  reset(context); 
} // hash()





/* ----- Testing, testing ... ---------------------------------------------- */

#include <time.h>
#include <stdio.h>

static void display_context(Context *context)
{
  unsigned i; 
  printf("+---------------------------------------------------+\n"); 
  printf("| I   = "); display_block(context->I);  printf("|\n"); 
  printf("| J   = "); display_block(context->J);  printf("|\n"); 
  printf("| L   = "); display_block(context->L);  printf("|\n"); 
  printf("| L'  = "); display_block(context->L1); printf("|\n"); 

  for (i = 0; i < 9; i++)
  {
    printf("| %d*J = ", i); 
    display_block(context->Js[i]); 
    printf("|\n"); 
  }

  printf("+---------------------------------------------------+\n"); 
}

int main()
{
  
  Block res; 
  Byte key [] = "This is a really great key.";
  Byte nonce [] = "Celebraties are awesome"; 
  Byte msg [] = "This i a great This is a great. sdkjf"; 
  unsigned key_bytes = strlen((const char *)key); 
  unsigned nonce_bytes = strlen((const char *)nonce); 
  unsigned msg_bytes = strlen((const char *)msg); 
  unsigned tau = 2;

  Context context;
  extract(&context, key, key_bytes);
  


  Block guy; zero_block(guy); 
  guy.word[3] = reverse_u32(tau);

 
  Byte *tags [3]; tags[0] = guy.byte; tags[1] = nonce; tags[2] = msg; 
  unsigned tag_bytes [] = {16, nonce_bytes, msg_bytes}; 
  unsigned num_tags = 3; 
    
  hash(res.byte, tags, num_tags, tag_bytes, &context); 
  display_block(res); printf("\n");  


  //display_context(&context);

  //  Block M, C;
  //  zero_block(M);
  //  zero_block(C);
  //  M.byte[1] = 2;
  //  display_block(M); printf("Sane? \n");
  //  Block fella [99]; 
  //  zero_block(fella[0]);
  //  cp_block(fella[1], context.Js[8]);
  //  int j = 0;
  //  for (int i = 2; i < 99; i++)
  //  {
  //    dot_inc(fella, i); 
  //    xor_block(C, M, fella[i-1]); 
  //    E(&C, C, i+1, j, &context);
  //    printf("%2d,%-2d ", i,j); display_block(C); printf("\n"); 
  //  }
  


return 0; 
}
/**
 * aez.c -- AEZv3, a Caesar submission proposed by Viet Tung Hoang, Ted Krovetz,
 * and Phillip Rogaway. This implementation is deesigned to be as fast as 
 * possible on the target architecture. 
 *
 * It uses a platform-independent implementation of AES (by Vincent Rijmen 
 * et al.) if the x86 AES-NI instruction set is unavailable (see 
 * rijndael-alg-fst.{h,c}). This is black-box AES, exceppt that the flag 
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


/* ----- AEZ context -------------------------------------------------------- */

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

  /* Tweak, key */
  Block I, L, L1, J [8]; 

} Context; 


/* ---- Constants ---------------------------------------------------------- */

const ALIGN(16) char z [16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};



/* ---- Various primitives ------------------------------------------------- */ 

#define MAX(a, b) (a < b ? b : a)

/* Reverse bytes of a 32-bit integer. */ 
#define reverse_u32(n) ( \
 ((n & 0x000000ffu) << 24) | \
 ((n & 0x0000ff00u) <<  8) | \
 ((n & 0x00ff0000u) >>  8) | \
 ((n & 0xff000000u) >> 24)   \
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
  #define toggle_endian(X) {} 
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


/* ----- AES-NI ------------------------------------------------------------ */ 

#ifdef __USE_AES_NI

/* Full 10-round AES. */ 
static __m128i aes10(__m128i M, Context *context) 
{
  M = _mm_aesenc_si128(M, context->I.block);
  M = _mm_aesenc_si128(M, context->L.block);
  M = _mm_aesenc_si128(M, context->J[1].block);
  M = _mm_aesenc_si128(M, context->I.block);
  M = _mm_aesenc_si128(M, context->L.block);
  M = _mm_aesenc_si128(M, context->J[1].block);
  M = _mm_aesenc_si128(M, context->I.block);
  M = _mm_aesenc_si128(M, context->L.block);
  M = _mm_aesenc_si128(M, context->J[1].block);
  return _mm_aesenclast_si128 (M, context->I.block);
} 

/*  AES4. */ 
static __m128i aes4_0(__m128i M, Context *context) 
{
  M = _mm_aesenc_si128(M, context->I.block);
  M = _mm_aesenc_si128(M, context->J[1].block); 
  M = _mm_aesenc_si128(M, context->L.block); 
  M = _mm_aesenc_si128(M, _mm_setzero_si128());
  return M; 
} 

static __m128i aes4_1(__m128i M, Context *context) 
{
  M = _mm_aesenc_si128(M, context->J[1].block);
  M = _mm_aesenc_si128(M, context->L.block); 
  M = _mm_aesenc_si128(M, context->I.block); 
  M = _mm_aesenc_si128(M, _mm_setzero_si128());
  return M; 
} 

static __m128i aes4_2(__m128i M, Context *context) 
{
  M = _mm_aesenc_si128(M, context->L.block); 
  M = _mm_aesenc_si128(M, context->I.block); 
  M = _mm_aesenc_si128(M, context->J[1].block); 
  M = _mm_aesenc_si128(M, context->I.block); 
  return M; 
} 

static __m128i aes4_short(__m128i M, __m128i K) 
{
  M = _mm_aesenc_si128(M ^ K, K); 
  M = _mm_aesenc_si128(M, K); 
  M = _mm_aesenc_si128(M, K);
  M = _mm_aesenc_si128(M, K);
  return M; 
} 

#endif


/* ---- AEZ tweaks --------------------------------------------------------- */

/*
 * Reverse byte order when computing tweaks. This is meant as an 
 * optimization for little endian systems. 
 */
static void rev_block(Byte X []) 
{
  Byte i, tmp[16];
  memcpy(tmp, X, 16);
  for (i=0; i<16; i++) X[i] = tmp[15-i];
}

/*
 * Multiply-by-two operation for key tweaking. 
 */
static void dot2(Byte X []) {
  rev_block(X); 
  Byte tmp = X[0];
  for (int i = 0; i < 15; i++)
    X[i] = (Byte)((X[i] << 1) | (X[i+1] >> 7));
  X[15] = (Byte)((X[15] << 1) ^ ((tmp >> 7) * 135));
  rev_block(X); 
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
static void variant(Context *context, int i, int j) 
{
  if (j > 8 && (j - 1) % 8 == 0)
    dot2(context->L.byte); 
}

/*
 * Reset tweak. 
 */
static void reset(Context *context)
{
  cp_block(context->L1, context->L);
}



/* ---- AEZ Tweakable blockcipher ------------------------------------------ */

void E(Block *Y, const Block X, int i, int j, Context *context)
{
  if (i == -1 && 0 <= j && j <= 7)
  {
    xor_block(*Y, X, context->J[j]);
    Y->block = aes10(Y->block, context);
  }

  else if (i == 0 && 0 <= j && j <= 7)
  {
    xor_block(*Y, X, context->J[j]);
    Y->block = aes4_0(Y->block, context);
  }

  else if (1 <= i && i <= 2 && j >= 1)
  {
    xor_block(*Y, X, context->J[j % 8]);
    xor_block(*Y, *Y, context->L1);
    if (i == 1) Y->block = aes4_1(Y->block, context);
    else        Y->block = aes4_2(Y->block, context);
  }

  else if (i >= 3 && j >= 1)
    assert(0); // Not implemented yet. j >= 1
  
  else if (i >= 3 && j == 0)
    assert(0); // Not implemented yet. j == 0

  else printf("Uh Oh!!!\n");

}



/* ----- AEZ Extract ------------------------------------------------------- */

void extract(Context *context, const char *key, unsigned key_bytes)
{
  int i, j, k, m;
  
  /* Number of blocks. */
  m = key_bytes / 128; 
  if (key_bytes % 128 > 0) m++; 
  m = MAX(m, 1); 

  Block C, X [3], buff, K;
  zero_block(buff); 
  zero_block(X[0]); 
  zero_block(X[1]); 
  zero_block(X[2]); 

  k = 0;
  for (j = 0; j < m-1; j++) // Full key blocks
  {
    load_block(K, &key[k]); k += 16;
    buff.lword[1] = j;

    for (i = 0; i < 3; i++)
    {
      buff.lword[0] = i;
      C.block = aes4_short(buff.block, *(__m128i *)z); 
      X[i].block ^= aes4_short(K.block, C.block); 
    }
  }

  j = key_bytes % 16; 
  if (j > 0) // Partial last block
  {
     zero_block(K); 
     cp_bytes(K.byte, &key[k], j); 
     K.byte[j] = 0x80;
     buff.lword[1] = 0; 
  }

  else // Full last block
  {
    load_block(K, &key[k]); 
    buff.lword[1] = m;
  } 

  for (i = 0; i < 3; i++)
  {
    buff.lword[0] = i;
    C.block = aes4_short(buff.block, *(__m128i *)z); 
    X[i].block ^= aes4_short(K.block, C.block); 
  }

  /* Set up key schedule and tweak context. */
  cp_block(context->I, X[0]);

  zero_block(context->J[0]); 
  cp_block(context->J[1], X[1]); 
  for (i = 0; i < 8; i++)
    dot_inc(context->J, i); 

  cp_block(context->L, X[2]); 
  cp_block(context->L1, X[2]); 

}



/* ----- Testing, testing ... ---------------------------------------------- */

#include <time.h>
#include <stdio.h>

static void display_block(const Block X) 
{
  for (int i = 0; i < 4; i ++)
    printf("0x%08x ", X.word[i]); 
}

static void display_context(Context *context)
{
  unsigned i; 
  printf("+----------------------------------------------------+\n"); 
  printf("| I    = "); display_block(context->I);  printf("|\n"); 
  printf("| L    = "); display_block(context->L);  printf("|\n"); 
  printf("| L'   = "); display_block(context->L1); printf("|\n"); 

  for (i = 0; i < 8; i++)
  {
    printf("| J[%d] = ", i); 
    display_block(context->J[i]); 
    printf("|\n"); 
  }

  printf("+----------------------------------------------------+\n"); 
}

int main()
{
  
  char key [] = "This is a great key.";
  int key_bytes = strlen((const char *)key); 
  
  Context context;
  extract(&context, key, key_bytes);
  //display_context(&context);

  Block M, C;
  zero_block(M);
  zero_block(C);
  for (int i = -1; i < 3; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      if (i > 0 && j == 0) continue;
      E(&C, M, i, j, &context);
      printf("%2d,%-2d ", i,j); display_block(C); printf("\n"); 
    }
  }
  


  return 0; 
}

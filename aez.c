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


/* ------------------------------------------------------------------------- */

#ifndef __USE_AES_NI 
#include "rijndael-alg-fst.h"
#else 
#include <wmmintrin.h>
#include <tmmintrin.h>
#endif 

#define MAX_DATA 3 /* Maximum length of additional data vector. */ 
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

  /* TODO What about laying a schedule like 0,I,0,J,0,L? */ 
#ifndef __USE_AES_NI
  Block k0[5], k1[5], k2[5], K[11];
#endif

  /* Tweaks, key. TODO Store 2*J, 4*J, 8*J, and 16*J. */
  Block I, L, L1, J, Js [9]; 

} Context; 


static void display_block(const Block X)
{
  for (int i = 0; i < 4; i ++)
    printf("0x%08x ", X.word[i]); 
}

static void display_context(Context *context)
{
  unsigned i; 
  printf("+---------------------------------------------------+\n"); 
  printf("| I   = "); display_block(context->I);  printf("|\n"); 
  printf("| J   = "); display_block(context->J);  printf("|\n"); 
  printf("d| L   = "); display_block(context->L);  printf("|\n"); 
  printf("| L'  = "); display_block(context->L1); printf("|\n"); 

  for (i = 0; i < 9; i++)
  {
    printf("| %d*J = ", i); 
    display_block(context->Js[i]); 
    printf("|\n"); 
  }

  printf("+---------------------------------------------------+\n"); 
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
 * Update doubling tweak `L`. 
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

  else { printf("Uh Oh!!!\n"); assert(0); } /* FIXME */

} // E()



/* ----- AEZ axu-hash, pseudorandom funcion. ------------------------------- */

void hash(Byte *delta, Byte *tags [], 
                unsigned num_tags, unsigned tag_bytes [],  Context *context)
{
  unsigned i, j, k, m; 
  Block H, X; 
  zero_block(H);

  Block offset [MAX_DATA + 4]; 
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
  
  cp_bytes(delta, H.byte, 16);
  reset(context); 
} // hash()


void prf(Byte *res, Byte *tags [], unsigned num_tags, unsigned tag_bytes [], 
                                                unsigned tau, Context *context)
{
  unsigned i, j, k, m = tau / 16; 
  if (tau % 16 > 0) m++; 
  m = max(m, 1); 
  
  Block H, X, ctr; zero_block(ctr); 
  hash(H.byte, tags, num_tags, tag_bytes, context); 

  for (i=0, j=0; i < m-1; i++)
  {
    xor_block(X, ctr, H); 
    E(&X, X, -1, 3, context); 
    cp_bytes(&res[j], X.byte, 16); 
    j += 16;

    k = 15; /* TODO, ctr doesn't match spec. */  
    do { ctr.byte[k]++; k--; } 
    while (ctr.byte[k+1] == 0); 
  }

  xor_block(X, ctr, H); 
  E(&X, X, -1, 3, context); 
  cp_bytes(&res[j], X.byte, tau - j); 
} // prf()



/* ----- AEZ-core. --------------------------------------------------------- */

void encipher_core(Byte *out, const Byte *in, unsigned bytes, Byte *tags [], 
      unsigned num_tags, unsigned tag_bytes [], Context *context, unsigned inv)
{
  Block Delta, X, Y, S, Sx, Sy, Mx, My, Mu, Mv, A, B, C; 
 
  const unsigned m = (bytes / 32) - 1; // No. i-blocks. 
  const unsigned d = bytes % 32; // Length of uv-block.
  unsigned i, j; 

  hash(Delta.byte, tags, num_tags, tag_bytes, context); 
  
  /* First pass. */ 
  zero_block(X);

  /* i-blocks */ 
  for (j = 1, i = 0; j <= m; j++)
  {
    load_block(A, &in[i + 16]); 
    E(&A, A, 1, j, context); 
    xor_bytes(A.byte, A.byte, &in[i], 16); 
    store_block(&out[i+16], A); // Wi
    E(&A, A, 0, 0, context);  
    xor_bytes(A.byte, A.byte, &in[i + 16], 16); 
    store_block(&out[i], A); // Xi
    xor_block(X, X, A); 
    update(context, j % 8 == 0); i += 32; 
  }
  reset(context); 

  /* uv-block */ 
  zero_block(Mu); zero_block(Mv);
  if (0 < d && d < 16) 
  {
    cp_bytes(Mu.byte, &in[bytes - 32 - d], d);
    Mu.byte[d] = 0x80; // Mu
    E(&A, Mu, 0, 4, context); 
    xor_block(X, X, A); 
  } 
  else if (0 < d && d < 32) 
  {
    load_block(Mu, &in[bytes - 32 - d]); 
    E(&A, Mu, 0, 4, context); // Mu
    xor_block(X, X, A); 
    cp_bytes(Mv.byte, &in[bytes - 16 - d], d - 16);
    Mv.byte[d - 16] = 0x80; 
    E(&A, Mv, 0, 5, context); // Mv 
    xor_block(X, X, A); 
  }

  /* xy-block, S */ 
  load_block(Mx, &in[bytes - 32]);
  load_block(My, &in[bytes - 16]); 
  E(&Sx, My, 0, 1 + inv, context);
  xor_block(Sx, Sx, X); 
  xor_block(Sx, Sx, Delta); 
  xor_block(Sx, Sx, Mx);
  E(&Sy, Sx, -1, 1 + inv, context); 
  xor_block(Sy, Sy, My); 
  xor_block(S, Sx, Sy); 
  
  /* Second pass. */ 
  zero_block(Y);
  
  /* i-blocks */ 
  for (j = 1, i = 0; j <= m; j++)
  {
    E(&A, S, 2, j, context); cp_block(B, A); // S'
    xor_bytes(A.byte, &out[i+16]/* Wi */, A.byte, 16); // Yi
    xor_block(Y, Y, A);
    xor_bytes(B.byte, &out[i]/* Xi */, B.byte, 16); // Zi
    E(&C, B, 0, 0, context); xor_block(C, C, A); // Ci'
    E(&A, C, 1, j, context); 
    xor_bytes(&out[i], B.byte, A.byte, 16); 
    store_block(&out[i+16], C); 
    update(context, j % 8 == 0); i += 32; 
  }
  reset(context); 
  
  /* uv-block */
  if (0 < d && d < 16) 
  {
    E(&A, S, -1, 4, context); 
    xor_block(Mu, Mu, A); zero_block(A); 
    cp_bytes(&out[bytes - 32 - d], Mu.byte, d); // Cu 
    cp_bytes(A.byte, Mu.byte, d); A.byte[d] = 0x80;
    E(&A, A, 0, 4, context); 
    xor_block(Y, Y, A); // Yu
  }
  else if (0 < d && d < 32)
  {
    E(&A, S, -1, 4, context); 
    xor_block(Mu, Mu, A); 
    store_block(&out[bytes - 32 - d], Mu); // Cu
    E(&A, Mu, 0, 4, context); 
    xor_block(Y, Y, A); // Yu
    E(&A, S, -1, 5, context);
    xor_block(Mv, Mv, A); zero_block(A); 
    cp_bytes(&out[bytes - 16 - d], Mv.byte, d - 16); // Cv
    cp_bytes(A.byte, Mv.byte, d - 16); A.byte[d - 16] = 0x80; 
    E(&A, A, 0, 5, context);
    xor_block(Y, Y, A); // Yv
  }

  /* xy-block */ 
  E(&A, Sy, -1, 2 - inv, context); 
  xor_block(A, A, Sx); // Cy
  store_block(&out[bytes - 16], A); 
  E(&A, A, 0, 2 - inv, context);
  xor_block(A, A, Y); 
  xor_block(A, A, Delta); 
  xor_block(A, A, Sy); 
  store_block(&out[bytes - 32], A); 
} // encipher()



/* ----- AEZ-tiny. --------------------------------------------------------- */

void encipher_tiny(Byte *out, const Byte *in, unsigned bytes, Byte *tags [], 
      unsigned num_tags, unsigned tag_bytes [], Context *context, unsigned inv)
{
  unsigned rounds, i, j=7, k;
  int step;
  Byte mask=0x00, pad=0x80, L[16], R[16], buff[32];
  Block Delta, tmp; 
  
  hash(Delta.byte, tags, num_tags, tag_bytes, context); 
  
  if      (bytes==1) rounds=24;
  else if (bytes==2) rounds=16;
  else if (bytes<16) rounds=10;
  else {        j=6; rounds=8; }
    
  /* Split (bytes*8)/2 bits into L and R. Beware: inay end in nibble. */
  memcpy(L, in,               (bytes+1)/2);
  memcpy(R, in + bytes/2, (bytes+1)/2);
  
  /* inust shift R left by half a byte */
  if (bytes & 1) 
  { 
    for (i=0; i < bytes/2; i++)
      R[i] = (Byte)((R[i] << 4) | (R[i+1] >> 4));
    R[bytes/2] = (Byte)(R[bytes/2] << 4);
    pad = 0x08; mask = 0xf0;
  }

  if (inv) 
  {
    if (bytes < 16) 
    {
      memset(tmp.byte, 0, 16); 
      memcpy(tmp.byte, in, bytes); 
      tmp.byte[0] |= 0x80;
      xor_block(tmp, tmp, Delta);
      E(&tmp, tmp, 0, 3, context); 
      L[0] ^= (tmp.byte[0] & 0x80);
    }
    i = rounds-1; step = -1;
  } 
  else 
  {
    i = 0; step = 1;
  }
  for (k=0; k < rounds/2; k++, i=(unsigned)((int)i+2*step)) 
  {
    memset(buff, 0, 16);
    memcpy(buff,R,(bytes+1)/2);
    buff[bytes/2] = (buff[bytes/2] & mask) | pad;
    xor_bytes(tmp.byte, buff, Delta.byte, 16);
    tmp.byte[15] ^= (Byte)i;
    E(&tmp, tmp, 0, j, context); 
    xor_bytes(L, L, tmp.byte, 16);

    memset(buff, 0, 16);
    memcpy(buff, L, (bytes + 1)/2);
    buff[bytes/2] = (buff[bytes/2] & mask) | pad;
    xor_bytes(tmp.byte, buff, Delta.byte, 16);
    tmp.byte[15] ^= (Byte)((int)i+step);
    E(&tmp, tmp, 0, j, context); 
    xor_bytes(R, R, tmp.byte, 16);
  }

  memcpy(buff,           R, bytes/2);
  memcpy(buff+bytes/2, L, (bytes+1)/2);
  if (bytes & 1) 
  {
    for (i=bytes-1; i>bytes/2; i--)
       buff[i] = (Byte)((buff[i] >> 4) | (buff[i-1] << 4));
     buff[bytes/2] = (Byte)((L[0] >> 4) | (R[bytes/2] & 0xf0));
  }

  memcpy(out, buff, bytes);
  if ((bytes < 16) && !inv) 
  {
    memset(buff+bytes,0,16-bytes); 
    buff[0] |= 0x80;
    xor_bytes(tmp.byte, buff, Delta.byte, 16);
    E(&tmp, tmp, 0, 3, context); 
    out[0] ^= (tmp.byte[0] & 0x80);
  }
} // encipher_tiny() 



/* ----- AEZ encipher. ----------------------------------------------------- */

void encipher(Byte *out, const Byte *in, unsigned bytes, Byte *tags [], 
      unsigned num_tags, unsigned tag_bytes [], Context *context, unsigned inv)
{
  if (bytes < 32) 
    encipher_tiny(out, in, bytes, tags, num_tags, tag_bytes, context, inv);

  else 
    encipher_core(out, in, bytes, tags, num_tags, tag_bytes, context, inv);

} // encipher()



/* ----- AEZ encrypt and decrypt. ------------------------------------------ */

int encrypt(Byte C[], Byte M[], unsigned msg_bytes, Byte N[], unsigned nonce_bytes,
            Byte *A[], unsigned data_bytes[], unsigned num_data, 
            unsigned auth_bytes, Context *context)
{
  unsigned tag_bytes [MAX_DATA + 2]; 
  Byte *tags [MAX_DATA + 2]; 
  Byte *X = malloc((msg_bytes + auth_bytes) * sizeof(Byte)); 
  
  Block tau; zero_block(tau); 
  tau.word[3] = reverse_u32(auth_bytes);
  tags[0] = tau.byte; tag_bytes[0] = 16; 
  tags[1] = N;      ; tag_bytes[1] = nonce_bytes; 
  for (int i = 0; i < num_data; i++) 
  {
    tags[i+2] = A[i]; tag_bytes[i+2] = data_bytes[i];
  }

  if (msg_bytes == 0)
    prf(C, tags, num_data + 2, tag_bytes, auth_bytes, context); 

  else 
  {
    memcpy(X, M, msg_bytes); memset(&X[msg_bytes], 0, auth_bytes); 
    encipher(C, X, msg_bytes + auth_bytes,
                            tags, num_data + 2, tag_bytes, context, 0); 
  }

  free(X);
  return 0; 
} // encrypt()


int decrypt(Byte M[], Byte C[], unsigned msg_bytes, Byte N[], unsigned nonce_bytes,
            Byte *A[], unsigned data_bytes[], unsigned num_data, 
            unsigned auth_bytes, Context *context)
{
  int res = 0, i; 
  unsigned tag_bytes [MAX_DATA + 2]; 
  Byte *tags [MAX_DATA + 2]; 
  Byte *X = malloc(msg_bytes * sizeof(Byte)); 
 
  Block tau; zero_block(tau); 
  tau.word[3] = reverse_u32(auth_bytes);
  tags[0] = tau.byte; tag_bytes[0] = 16; 
  tags[1] = N;      ; tag_bytes[1] = nonce_bytes; 
  for (i = 0; i < num_data; i++) 
  {
    tags[i+2] = A[i]; tag_bytes[i+2] = data_bytes[i];
  }
  
  if (msg_bytes == auth_bytes)
  {
    prf(X, tags, num_data + 2, tag_bytes, auth_bytes, context); 
    for (i = 0; i < msg_bytes; i++)
      res |= X[i] != C[i];
  }

  else
  {
    encipher(X, C, msg_bytes, tags, num_data + 2, tag_bytes, context, 1);
    for (i = msg_bytes - auth_bytes; i < msg_bytes; i++)
      res |= X[i] != 0; 
  }

  if (res != INVALID)
    memcpy(M, X, msg_bytes - auth_bytes); 

  free(X); 
  return (res ? INVALID : 0); 
} // encrypt()
            





/* ----- Testing, testing ... ---------------------------------------------- */

#include <time.h>
#include <stdio.h>

#define HZ (2.9e9) 
#define TRIALS 100000

void benchmark() {

  static const int msg_len [] = {64,    128,   256,   512, 
                                 1024,  4096,  10000, 100000,
                                 1<<18, 1<<20, 1<<22 }; 
  static const int num_msg_lens = 7; 
  unsigned i, j, auth_bytes = 16, key_bytes = 16; 
  
  Context context; 
  ALIGN(16) Block key;   memset(key.byte, 0, 16); 
  ALIGN(16) Block nonce; memset(nonce.byte, 0, 16); 
  extract(&context, key.byte, key_bytes);

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
      encrypt(ciphertext, message, msg_len[i], nonce.byte, 16, 
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
  if (decrypt(plaintext, ciphertext, msg_len[i] + auth_bytes, nonce.byte, 16,
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
  extract(&context, key, key_bytes); 
  //display_context(&context); 
  for (i = 0; i < msg_len; i++)
  {
    encrypt(ciphertext, message, i, nonce, nonce_bytes, 
          NULL, NULL, 0, auth_bytes, &context); 
   
    xor_bytes(sum.byte, sum.byte, ciphertext, 16); 
  
    res = decrypt(plaintext, ciphertext, i + auth_bytes, nonce, nonce_bytes, 
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

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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "aez.h"


void xor_bytes(Byte X [], const Byte Y [], const Byte Z [], unsigned n)
{
  for (int i = 0; i < n; i++)
    X[i] = Y[i] ^ Z[i]; 
}


/* ----- AES calls. -------------------------------------------------------- */

#ifdef __USE_AES_NI
static __m128i aes(__m128i M, __m128i K[])
{
  M = _mm_aesenc_si128(M, K[0]);
  M = _mm_aesenc_si128(M, K[1]);
  M = _mm_aesenc_si128(M, K[2]);
  M = _mm_aesenc_si128(M, K[0]);
  M = _mm_aesenc_si128(M, K[1]);
  M = _mm_aesenc_si128(M, K[2]);
  M = _mm_aesenc_si128(M, K[0]);
  M = _mm_aesenc_si128(M, K[1]);
  M = _mm_aesenc_si128(M, K[2]);
  return _mm_aesenc_si128(M, K[0]);
}

static __m128i aes4(__m128i M, __m128i K[], int a, int b, int c, int d)
{
  M = _mm_aesenc_si128(M, K[a]);
  M = _mm_aesenc_si128(M, K[b]);
  M = _mm_aesenc_si128(M, K[c]);
  return _mm_aesenc_si128 (M, K[d]);
}
#endif

static void aes4_short(Block *Y, Block X, const Block K) 
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
  cp_block(context->L1, context->K[1]);
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
  cp_block(context->K[0], X[0]); toggle_endian(context->K[0]); 
  cp_block(context->K[2], X[1]); toggle_endian(context->K[2]); 
  cp_block(context->K[1], X[2]); toggle_endian(context->K[1]);
  zero_block(context->K[3]); 

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
  zero_block(context->k2[0]); zero_block(context->Klong[0]); 

  cp_block(context->k0[2], context->K[2]); cp_block(context->k1[1], context->K[2]); 
  cp_block(context->k2[3], context->K[2]); cp_block(context->Klong[3], context->K[2]);
  cp_block(context->Klong[6], context->K[2]);  cp_block(context->Klong[9], context->K[2]);

  cp_block(context->k0[1], context->K[0]); cp_block(context->k1[3], context->K[0]); 
  cp_block(context->k2[2], context->K[0]); cp_block(context->k2[4], context->K[0]); 
  cp_block(context->Klong[1], context->K[0]);  cp_block(context->Klong[4], context->K[0]);
  cp_block(context->Klong[7], context->K[0]);  cp_block(context->Klong[10], context->K[0]);

  cp_block(context->k0[3], context->K[1]); cp_block(context->k1[2], context->K[1]); 
  cp_block(context->k2[1], context->K[1]); cp_block(context->Klong[2], context->K[1]);
  cp_block(context->Klong[5], context->K[1]);  cp_block(context->Klong[8], context->K[1]);
#endif

} // extract()



/* ---- AEZ Tweakable blockcipher. ----------------------------------------- */

static void E(Block *Y, Block X, int i, int j, Context *context)
{
  if (i == -1 && 0 <= j && j <= 7)
  {
    xor_block(X, X, context->Js[j]);
#ifdef __USE_AES_NI
    Y->block = aes(X.block, (__m128i *)context->K); 
#else 
    rijndaelEncryptRound((uint32_t *)context->Klong, 11, X.byte, 10); 
    cp_block(*Y, X); 
#endif 
  }

  else if (i == 0 && 0 <= j && j <= 7)
  {
    xor_block(X, X, context->Js[j]);
#ifdef __USE_AES_NI
    Y->block = aes4(X.block, (__m128i *)context->K, 0, 2, 1, 3); 
#else
    rijndaelEncryptRound((uint32_t *)context->k0, 10, X.byte, 4);  
    cp_block(*Y, X); 
#endif
  }

  else if (1 <= i && i <= 2 && j >= 1)
  {
    xor_block(X, X, context->Js[j % 8]);
    xor_block(X, X, context->L1);
    if (i == 1)
    {
#ifdef __USE_AES_NI
      Y->block = aes4(X.block, (__m128i *)context->K, 2, 1, 0, 3);
#else
      rijndaelEncryptRound((uint32_t *)context->k1, 10, X.byte, 4);  
      cp_block(*Y, X); 
#endif
    }
    else
    { 
#ifdef __USE_AES_NI
      Y->block = aes4(X.block, (__m128i *)context->K, 1, 0, 2, 0);
#else
      rijndaelEncryptRound((uint32_t *)context->k2, 10, X.byte, 4);  
      cp_block(*Y, X); 
#endif
    }
  }

  else if (i >= 3 && j >= 1)
  {
    /* The J-tweak is mixed in hash(). */ 
    xor_block(X, X, context->Js[j % 8]); 
    xor_block(X, X, context->L1);
#ifdef __USE_AES_NI
    Y->block = aes4(X.block, (__m128i *)context->K, 0, 2, 1, 3);
#else
    rijndaelEncryptRound((uint32_t *)context->k0, 10, X.byte, 4);  
    cp_block(*Y, X); 
#endif
  }

  else
  { 
    /* The J-tweak is mixed in hash(). */ 
#ifdef __USE_AES_NI
    Y->block = aes4(X.block, (__m128i *)context->K, 0, 2, 1, 3);
#else
    rijndaelEncryptRound((uint32_t *)context->k0, 10, X.byte, 4);  
    cp_block(*Y, X); 
#endif
  }

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
    load_block(My, &in[i+16]); E(&A, My, 1, j, context); 
    load_block(Mx, &in[i]);  xor_block(A, A, Mx); // Wi
    E(&B, A, 0, 0, context); xor_block(B, B, My); // Xi
    xor_block(X, X, B); 
    store_block(&out[i], B); 
    store_block(&out[i+16], A); 
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
    E(&A, S, 2, j, context);
    load_block(Mx, &out[i+16]); 
    load_block(My, &out[i]); 
    xor_block(B, A, Mx); 
    xor_block(C, A, My); 
    E(&Mx, C, 0, 0, context); 
    xor_block(Mx, Mx, B); 
    E(&My, Mx, 1, j, context); 
    xor_block(My, My, C); 
    store_block(&out[i], My); 
    store_block(&out[i+16], Mx); 
    xor_block(Y, Y, B); 
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
  memcpy(L, in,           (bytes+1)/2);
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
 
  Block tau; zero_block(tau); 
  tau.word[3] = reverse_u32(auth_bytes*8); 
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
    Byte *X = malloc((msg_bytes + auth_bytes) * sizeof(Byte)); 
    memcpy(X, M, msg_bytes); memset(&X[msg_bytes], 0, auth_bytes); 
    encipher(C, X, msg_bytes + auth_bytes,
                            tags, num_data + 2, tag_bytes, context, 0); 
    free(X);
  }

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
  tau.word[3] = reverse_u32(auth_bytes*8); 
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

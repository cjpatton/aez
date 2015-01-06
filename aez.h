/**
 * aez.h -- AEZv3, a Caesar submission proposed by Viet Tung Hoang, Ted Krovetz,
 * and Phil Rogaway. It uses a platform-independent implementation of AES (by 
 * Vincent Rijmen et al.) if the x86 AES-NI instruction set is unavailable (see 
 * the  provided rijndael-alg-fst.{h,c}). This code is unmodified, exceppt that 
 * the flag `INTERMEDIATE_VALUE_KAT` is set. 
 *
 * Written by Chris Patton <chrispatton@gmail.com> and dedicated to the public
 * domain. 
 *
 * Last modified 29 Dec 2014. 
 */

#ifndef AEZ_H
#define AEZ_H

/*
 * Architecture flags. If the platform supports the AES-NI and SSSE3 instruction 
 * sets, set __USE_AES_NI; if the platform doesn't have hardware support for AES, 
 * but is a 64-bit architecture, then set __ARCH_64; if the system is 32-bit, un-
 * set both __USE_AES_NI and __ARCH_64. These are set by the Makefile.  
 */
//#define __USE_AES_NI
//#define __ARCH_64



/* ------------------------------------------------------------------------- */

#ifndef __USE_AES_NI 
#include "rijndael-alg-fst.h"
#else 
#include <wmmintrin.h>
#include <tmmintrin.h>
#endif 

#define MAX_DATA 10  /* Maximum length of additional data vector. */ 
#define INVALID -1   /* Reject plaintext (inauthentic). */ 
#ifdef __USE_AES_NI
  #define USING_AES_NI 1
#else 
  #define USING_AES_NI 0
#endif

/* AES input/output/keys are block aligned in order to support AES-NI. */ 
#define ALIGN(n) __attribute__ ((aligned(n))) 



/* ----- AEZ context. -------------------------------------------------------*/

#include <stdint.h>

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


/* 
 * AEZ context. For AES-NI, the state size is 14 blocks (or 224 bytes). Two 
 * of these (K[3] and Js[0]) are just zero, so one or both could potentially
 * be elminated. The odd-valued i*J tweaks could be elminated from the state
 * since i*J = i-1*J ^ 1*J for odd i. For software AES, the context is 
 * substantially larger since we explicitly lay out the key schedules. 
 */
typedef struct {

  Block L1,     /* Cache for doubling L-tweak. */
        K [4],  /* K[0]=I, K[1]=L, K[2]=J, K[3]=0 */
        Js [9]; /* Js = [0*J, 1*J, 2*J ... 8*J]. */

#ifndef __USE_AES_NI
  Block k0[5], k1[5], k2[5], Klong[11];
#endif

} Context; 



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
void xor_bytes(Byte X [], const Byte Y [], const Byte Z [], unsigned n);



/* ---- High level calls. -------------------------------------------------- */

void aez_extract(Context *context, const Byte *key, unsigned key_bytes);

void aez_hash(Byte *delta, Byte *tags [], 
                unsigned num_tags, unsigned tag_bytes [],  Context *context);

void aez_prf(Byte *res, Byte *tags [], unsigned num_tags, unsigned tag_bytes [], 
                                                unsigned tau, Context *context);

void encipher_core(Byte *out, const Byte *in, unsigned bytes, Byte *tags [], 
      unsigned num_tags, unsigned tag_bytes [], Context *context, 
      unsigned auth_bytes, unsigned inv);

void encipher_tiny(Byte *out, const Byte *in, unsigned bytes, Byte *tags [], 
      unsigned num_tags, unsigned tag_bytes [], Context *context, unsigned inv);

void aez_encipher(Byte *out, const Byte *in, unsigned bytes, Byte *tags [], 
      unsigned num_tags, unsigned tag_bytes [], Context *context, 
      unsigned auth_bytes, unsigned inv);

int aez_encrypt(Byte C[], Byte M[], unsigned msg_bytes, Byte N[], unsigned nonce_bytes,
            Byte *A[], unsigned data_bytes[], unsigned num_data, 
            unsigned auth_bytes, Context *context);

int aez_decrypt(Byte M[], Byte C[], unsigned msg_bytes, Byte N[], unsigned nonce_bytes,
            Byte *A[], unsigned data_bytes[], unsigned num_data, 
            unsigned auth_bytes, Context *context);


/* ---- Acessors for Python interface. ------------------------------------- */

int get_max_data(); /* Access constants in Python via Ctypes. */  
int get_invalid(); 
int using_aes_ni(); 

#endif // AEZ_H

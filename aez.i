%module aez
%{
  #include "aez.h"
%}

%include "stdint.i"

typedef uint8_t Byte; 
%apply char[] { Byte * }; 
%apply char[] { Byte [] }; 

typedef struct {

  Block L1,     /* Cache for doubling L-tweak. */
        K [4],  /* K[0]=I, K[1]=L, K[2]=J, K[3]=0 */
        Js [9]; /* Js = [0*J, 1*J, 2*J ... 8*J]. */

#ifndef __USE_AES_NI
  Block k0[5], k1[5], k2[5], Klong[11];
#endif

} Context; 

void extract(Context *context, const Byte *key, unsigned key_bytes);

void hash(Byte *delta, Byte *tags [], 
                unsigned num_tags, unsigned tag_bytes [],  Context *context);

void prf(Byte *res, Byte *tags [], unsigned num_tags, unsigned tag_bytes [], 
                                                unsigned tau, Context *context);

void encipher_core(Byte *out, const Byte *in, unsigned bytes, Byte *tags [], 
      unsigned num_tags, unsigned tag_bytes [], Context *context, unsigned inv);

void encipher_tiny(Byte *out, const Byte *in, unsigned bytes, Byte *tags [], 
      unsigned num_tags, unsigned tag_bytes [], Context *context, unsigned inv);

void encipher(Byte *out, const Byte *in, unsigned bytes, Byte *tags [], 
      unsigned num_tags, unsigned tag_bytes [], Context *context, unsigned inv);

int aez_encrypt(Byte C[], Byte M[], unsigned msg_bytes, Byte N[], unsigned nonce_bytes,
            Byte *A[], unsigned data_bytes[], unsigned num_data, 
            unsigned auth_bytes, Context *context);

int aez_decrypt(Byte M[], Byte C[], unsigned msg_bytes, Byte N[], unsigned nonce_bytes,
            Byte *A[], unsigned data_bytes[], unsigned num_data, 
            unsigned auth_bytes, Context *context);


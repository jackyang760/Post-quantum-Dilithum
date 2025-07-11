#ifndef ASCON_HASH_H
#define ASCON_HASH_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "ascon.h"
#include "permutations.h"
// #include "printstate.h"
#include "word.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define ASCON_NAMESPACE(s) pqcrystals_kyber_ascon_ref_##s

#define ascon_xof_P12 ASCON_NAMESPACE(ascon_xof_P12)
void ascon_xof_P12(uint8_t *out,size_t outlen, const uint8_t *in, size_t len);

#define ascon_init ASCON_NAMESPACE(ascon_init)
void ascon_init(ascon_state_t *state);

#define ascon_absorb ASCON_NAMESPACE(ascon_absorb)
void ascon_absorb(ascon_state_t *state, const uint8_t *data, size_t len);

#define ascon_finalize ASCON_NAMESPACE(ascon_finalize)
void ascon_finalize(ascon_state_t *state);

#define ascon_squeeze ASCON_NAMESPACE(ascon_squeeze)
void ascon_squeeze(ascon_state_t *state, uint8_t *out, size_t outlen);

#define ascon_xof ASCON_NAMESPACE(ascon_xof)
void ascon_xof(uint8_t *out,size_t outlen, const uint8_t *in, size_t len);

#define ascon_xof_init ASCON_NAMESPACE(ascon_xof_init)
void ascon_xof_init(ascon_state_t *state, 
    const uint8_t seed[SEEDBYTES],
    uint16_t nonce);

#define ascon_xof_squeezeblocks ASCON_NAMESPACE(ascon_xof_squeezeblocks)
void ascon_xof_squeezeblocks(ascon_state_t *state, 
    uint8_t *out, 
    size_t nblocks);

#endif
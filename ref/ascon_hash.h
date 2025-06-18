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

#define FIPS202_NAMESPACE(s) pqcrystals_kyber_fips202_ref_##s

#define ascon_xof FIPS202_NAMESPACE(ascon_xof)
void ascon_xof(uint8_t *out,size_t outlen, const uint8_t *in, size_t len);
#endif
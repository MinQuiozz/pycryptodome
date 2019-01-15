#ifndef _MONT_H
#define _MONT_H

#include "common.h"

/*
 * How many numbers a scratchpad for temporary computations should contain.
 * Each number is composed by a set of uint64_t words (whose size depends on
 * the context).
 */
#define SCRATCHPAD_NR 5

typedef struct mont_context {
    unsigned words;
    unsigned bytes;
    uint64_t *modulus;
    uint64_t *modulus_min_2;
    uint64_t *r2_mod_n;     /* R^2 mod N */
    uint64_t *r_mod_n;      /* R mod N */
    uint64_t m0;
    uint64_t *one;
} MontContext;

void mont_context_free(MontContext *ctx);
size_t mont_bytes(const MontContext *ctx);

int mont_number(uint64_t **out, unsigned count, const struct mont_context *ctx);
int mont_from_bytes(uint64_t **out, const uint8_t *number, size_t len, const MontContext *ctx);
int mont_to_bytes(uint8_t *number, const uint64_t* mont_number, const MontContext *ctx);
int mont_add(uint64_t* out, const uint64_t* a, const uint64_t* b, uint64_t *tmp, const MontContext *ctx);
int mont_mult(uint64_t* out, const uint64_t* a, const uint64_t *b, uint64_t *tmp, const MontContext *ctx);
int mont_shift_left(uint64_t* out, const uint64_t* a, uint64_t k, const MontContext *ctx);
int mont_sub(uint64_t *out, const uint64_t *a, const uint64_t *b, uint64_t *tmp, const MontContext *ctx);
int mont_inv_prime(uint64_t *out, uint64_t *a, const MontContext *ctx);
int mont_set(uint64_t *out, uint64_t x, uint64_t* tmp, const MontContext *ctx);
int mont_context_init(MontContext **out, const uint8_t *modulus, size_t mod_len);

int mont_is_zero(const uint64_t *a, const MontContext *ctx);
int mont_is_one(const uint64_t *a, const MontContext *ctx);
int mont_is_equal(const uint64_t *a, const uint64_t *b, const MontContext *ctx);
int mont_copy(uint64_t *out, const uint64_t *a, const MontContext *ctx);
int mont_select(uint64_t *out, const uint64_t *a, const uint64_t *b, unsigned cond, const MontContext *ctx);
int mont_clear(uint64_t *out, const MontContext *ctx);

#endif

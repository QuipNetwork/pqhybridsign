/* SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Links against the built pqhybridsign-cffi library, signs and verifies
 * under H1 (stateless) and H5 (stateful), and exits nonzero on any
 * failure. See tests/c/run.sh for how this is built and run.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqhybridsign.h"

static int fail(const char *what, int32_t rc) {
    fprintf(stderr, "FAIL: %s (rc=%d: %s)\n", what, rc, pqhs_error_message(rc));
    return 1;
}

static int check_h1(void) {
    size_t sk_len, pk_len, sig_max_len;
    if (pqhs_secret_key_len(1, &sk_len) != PQHS_OK) return fail("h1 secret_key_len", 1);
    if (pqhs_public_key_len(1, &pk_len) != PQHS_OK) return fail("h1 public_key_len", 1);
    if (pqhs_signature_len(1, &sig_max_len) != PQHS_OK) return fail("h1 signature_len", 1);

    uint8_t *sk = calloc(1, sk_len);
    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sig = calloc(1, sig_max_len);
    if (!sk || !pk || !sig) {
        fprintf(stderr, "FAIL: h1 allocation\n");
        return 1;
    }

    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));

    int32_t rc = pqhs_keygen_from_seed(1, seed, sizeof(seed), sk, sk_len, pk, pk_len);
    if (rc != PQHS_OK) return fail("h1 keygen_from_seed", rc);

    const uint8_t msg[] = "the message the C test signs";
    const uint8_t ctx[] = "c-abi-test";
    size_t sig_len = 0;
    rc = pqhs_sign_deterministic(1, sk, sk_len, msg, sizeof(msg), ctx, sizeof(ctx),
                                  (const uint8_t *)"nonce", 5, sig, sig_max_len, &sig_len);
    if (rc != PQHS_OK) return fail("h1 sign_deterministic", rc);

    bool valid = false;
    rc = pqhs_verify(1, pk, pk_len, msg, sizeof(msg), ctx, sizeof(ctx), sig, sig_len, &valid);
    if (rc != PQHS_OK) return fail("h1 verify call", rc);
    if (!valid) {
        fprintf(stderr, "FAIL: h1 signature did not verify\n");
        return 1;
    }

    /* A tampered message must fail to verify, not error. */
    const uint8_t other[] = "a different message";
    bool still_valid = true;
    rc = pqhs_verify(1, pk, pk_len, other, sizeof(other), ctx, sizeof(ctx), sig, sig_len,
                      &still_valid);
    if (rc != PQHS_OK) return fail("h1 verify (tampered) call", rc);
    if (still_valid) {
        fprintf(stderr, "FAIL: h1 tampered message verified\n");
        return 1;
    }

    free(sk);
    free(pk);
    free(sig);
    return 0;
}

/* An in-memory journal: fine for a smoke test, never appropriate for real
 * key material, since it does not survive a crash. */
static uint32_t g_committed_leaf = 0;
static int g_have_committed = 0;

static int32_t journal_commit(void *ctx, uint32_t leaf) {
    (void)ctx;
    g_committed_leaf = leaf;
    g_have_committed = 1;
    return 0;
}

static uint32_t journal_next_leaf(void *ctx) {
    (void)ctx;
    return g_have_committed ? g_committed_leaf + 1 : 0;
}

static int check_h5(void) {
    size_t sk_len, pk_len, sig_max_len;
    if (pqhs_secret_key_len(5, &sk_len) != PQHS_OK) return fail("h5 secret_key_len", 1);
    if (pqhs_public_key_len(5, &pk_len) != PQHS_OK) return fail("h5 public_key_len", 1);
    if (pqhs_signature_len(5, &sig_max_len) != PQHS_OK) return fail("h5 signature_len", 1);

    uint8_t *sk = calloc(1, sk_len);
    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sk_out = calloc(1, sk_len);
    uint8_t *sig = calloc(1, sig_max_len);
    if (!sk || !pk || !sk_out || !sig) {
        fprintf(stderr, "FAIL: h5 allocation\n");
        return 1;
    }

    uint8_t seed[32];
    memset(seed, 0x99, sizeof(seed));

    int32_t rc = pqhs_keygen_stateful_from_seed(5, seed, sizeof(seed), 4, sk, sk_len, pk, pk_len);
    if (rc != PQHS_OK) return fail("h5 keygen_stateful_from_seed", rc);

    PqhsLeafJournal journal = {
        .ctx = NULL,
        .commit = journal_commit,
        .next_leaf = journal_next_leaf,
    };

    const uint8_t msg[] = "a stateful message";
    size_t sig_len = 0;
    rc = pqhs_sign_stateful(5, sk, sk_len, &journal, msg, sizeof(msg), NULL, 0, sk_out, sk_len,
                             sig, sig_max_len, &sig_len);
    if (rc != PQHS_OK) return fail("h5 sign_stateful", rc);
    if (memcmp(sk, sk_out, sk_len) == 0) {
        fprintf(stderr, "FAIL: h5 exported key did not advance past the spent leaf\n");
        return 1;
    }

    bool valid = false;
    rc = pqhs_verify(5, pk, pk_len, msg, sizeof(msg), NULL, 0, sig, sig_len, &valid);
    if (rc != PQHS_OK) return fail("h5 verify call", rc);
    if (!valid) {
        fprintf(stderr, "FAIL: h5 stateful signature did not verify\n");
        return 1;
    }

    free(sk);
    free(pk);
    free(sk_out);
    free(sig);
    return 0;
}

static int check_null_pointer_and_profile(void) {
    bool valid = true;
    /* A null pk paired with a nonzero length is a null-pointer error, never
     * a dereference. */
    int32_t rc = pqhs_verify(1, NULL, 64, (const uint8_t *)"m", 1, NULL, 0,
                              (const uint8_t *)"s", 1, &valid);
    if (rc != PQHS_ERR_NULL_POINTER) return fail("null pk rejected", rc);

    const char *profile = pqhs_profile_name();
    if (!profile || strncmp(profile, "shrincs-", 8) != 0) {
        fprintf(stderr, "FAIL: unexpected profile name: %s\n", profile ? profile : "(null)");
        return 1;
    }
    return 0;
}

int main(void) {
    int failures = 0;
    failures += check_h1();
    failures += check_h5();
    failures += check_null_pointer_and_profile();

    if (failures == 0) {
        printf("OK: all C ABI checks passed\n");
        return 0;
    }
    fprintf(stderr, "%d C ABI check(s) failed\n", failures);
    return 1;
}

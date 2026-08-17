/* SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Links against the built pqhybridsign-cffi archive, exercises the happy
 * path under H1 (stateless) and H5 (stateful), and then walks the error
 * cases a C integrator is most likely to hit by accident: a short or
 * oversized output buffer, the wrong entry point for a suite, a null
 * out-parameter, an exhausted leaf budget, a journal that refuses to
 * commit, a journal that does not belong to the key it was handed, a
 * journal with a null callback, an aliased sk/sk_out pair, and
 * malformed verify input.
 *
 * The error cases matter more than the happy path here. Every one of them
 * is a defect this file failed to catch at least once, and each asserts the
 * same property: a call that reports an error must have changed nothing --
 * no leaf spent, no key advanced, no signature half-written -- so that the
 * error code is safe to act on. Exits nonzero on any failure. See
 * tests/c/run.sh for how this is built and run.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqhybridsign.h"

static int fail(const char *what, int rc) {
    fprintf(stderr, "FAIL: %s (rc=%d: %s)\n", what, rc, pqhs_error_message(rc));
    return 1;
}

/* Asserts `rc == expected` and names the case on mismatch. */
static int expect_rc(const char *what, int rc, int expected) {
    if (rc == expected) return 0;
    fprintf(stderr, "FAIL: %s: expected rc=%d (%s), got rc=%d (%s)\n", what, expected,
            pqhs_error_message(expected), rc, pqhs_error_message(rc));
    return 1;
}

static int expect_true(const char *what, int condition) {
    if (condition) return 0;
    fprintf(stderr, "FAIL: %s\n", what);
    return 1;
}

/* ------------------------------------------------------------------ */
/* H1: stateless sign and verify                                       */
/* ------------------------------------------------------------------ */

static int check_h1(void) {
    size_t sk_len, pk_len, sig_max_len;
    if (pqhs_secret_key_len(1, &sk_len) != PQHS_OK) return fail("h1 secret_key_len", 1);
    if (pqhs_public_key_len(1, &pk_len) != PQHS_OK) return fail("h1 public_key_len", 1);
    if (pqhs_signature_len(1, &sig_max_len) != PQHS_OK) return fail("h1 signature_len", 1);

    int failures = 0;
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sig = calloc(1, sig_max_len);
    if (!sk || !pk || !sig) {
        fprintf(stderr, "FAIL: h1 allocation\n");
        failures = 1;
        goto done;
    }

    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));

    int rc = pqhs_keygen_from_seed(1, seed, sizeof(seed), sk, sk_len, pk, pk_len);
    if (rc != PQHS_OK) {
        failures = fail("h1 keygen_from_seed", rc);
        goto done;
    }

    const uint8_t msg[] = "the message the C test signs";
    const uint8_t ctx[] = "c-abi-test";
    size_t sig_len = 0;
    rc = pqhs_sign_deterministic(1, sk, sk_len, msg, sizeof(msg), ctx, sizeof(ctx),
                                  (const uint8_t *)"nonce", 5, sig, sig_max_len, &sig_len);
    if (rc != PQHS_OK) {
        failures = fail("h1 sign_deterministic", rc);
        goto done;
    }

    bool valid = false;
    rc = pqhs_verify(1, pk, pk_len, msg, sizeof(msg), ctx, sizeof(ctx), sig, sig_len, &valid);
    failures += expect_rc("h1 verify call", rc, PQHS_OK);
    failures += expect_true("h1 signature verified", valid);

    /* A tampered message must fail to verify, not error. */
    const uint8_t other[] = "a different message";
    bool still_valid = true;
    rc = pqhs_verify(1, pk, pk_len, other, sizeof(other), ctx, sizeof(ctx), sig, sig_len,
                      &still_valid);
    failures += expect_rc("h1 verify (tampered) call", rc, PQHS_OK);
    failures += expect_true("h1 tampered message rejected", !still_valid);

done:
    free(sk);
    free(pk);
    free(sig);
    return failures;
}

/* ------------------------------------------------------------------ */
/* An in-memory leaf journal                                           */
/* ------------------------------------------------------------------ */

/* Fine for a smoke test, never appropriate for real key material, since it
 * does not survive a crash. The callbacks return `int` because that is what
 * the header declares; `int32_t` is the same type on every platform this
 * builds for today, but the C standard does not promise it. */
static uint32_t g_committed_leaf = 0;
static int g_have_committed = 0;
static int g_commit_calls = 0;
/* The durable binding, alongside the counter: which key this journal is the
 * leaf record for. `g_have_bound == 0` is a journal that has never been
 * bound to any key. */
static uint8_t g_bound_key[PQHS_KEY_IDENTITY_LEN];
static int g_have_bound = 0;

static void journal_reset(void) {
    g_committed_leaf = 0;
    g_have_committed = 0;
    g_commit_calls = 0;
    memset(g_bound_key, 0, sizeof(g_bound_key));
    g_have_bound = 0;
}

static int journal_commit(void *ctx, uint32_t leaf) {
    (void)ctx;
    g_commit_calls += 1;
    g_committed_leaf = leaf;
    g_have_committed = 1;
    return 0;
}

static uint32_t journal_next_leaf(void *ctx) {
    (void)ctx;
    return g_have_committed ? g_committed_leaf + 1 : 0;
}

static int journal_bound_key(void *ctx, uint8_t *out, size_t out_len) {
    (void)ctx;
    if (!g_have_bound) return 1;
    if (out == NULL || out_len != PQHS_KEY_IDENTITY_LEN) return 1;
    memcpy(out, g_bound_key, out_len);
    return 0;
}

static int journal_bind_key(void *ctx, const uint8_t *key, size_t key_len) {
    (void)ctx;
    if (key == NULL || key_len != PQHS_KEY_IDENTITY_LEN) return 1;
    memcpy(g_bound_key, key, key_len);
    g_have_bound = 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* An in-memory stateless budget store                                 */
/* ------------------------------------------------------------------ */

/* The stateless counterpart of the journal above, and just as unfit for real
 * key material: it does not survive a crash, and a store that forgets lets
 * the few-time bound of specification section 21 be exceeded silently after
 * a restart. One entry is enough here -- these tests use one key at a time.
 *
 * `budget_consumed` returns nonzero only for material it has genuinely never
 * tracked, never for a read it could not perform, because nonzero reads as a
 * full budget. */
static uint8_t g_budget_key[PQHS_BUDGET_KEY_LEN];
static uint64_t g_budget_count = 0;
static int g_have_budget_entry = 0;
/* When set, `budget_record` reports that nothing was stored. */
static int g_budget_record_fails = 0;

static void budget_reset(void) {
    memset(g_budget_key, 0, sizeof(g_budget_key));
    g_budget_count = 0;
    g_have_budget_entry = 0;
    g_budget_record_fails = 0;
}

static int budget_consumed(void *ctx, const uint8_t *key, size_t key_len,
                           uint64_t *out_consumed) {
    (void)ctx;
    if (key == NULL || key_len != PQHS_BUDGET_KEY_LEN || out_consumed == NULL) return 1;
    if (!g_have_budget_entry) return 1;
    if (memcmp(key, g_budget_key, key_len) != 0) return 1;
    *out_consumed = g_budget_count;
    return 0;
}

static int budget_record(void *ctx, const uint8_t *key, size_t key_len, uint64_t count) {
    (void)ctx;
    if (key == NULL || key_len != PQHS_BUDGET_KEY_LEN) return 1;
    if (g_budget_record_fails) return 1;
    memcpy(g_budget_key, key, key_len);
    g_budget_count = count;
    g_have_budget_entry = 1;
    return 0;
}

static PqhsStatelessBudget make_budget(void) {
    PqhsStatelessBudget budget = {
        .ctx = NULL,
        .consumed = budget_consumed,
        .record = budget_record,
    };
    return budget;
}

/* Reset the journal and bind it to the key `pk` names, as an integrator does
 * once when a key's durable store is created. Returns the number of
 * failures. */
static int journal_provision(uint8_t suite, const uint8_t *pk, size_t pk_len) {
    PqhsLeafJournal journal = {
        .ctx = NULL,
        .commit = journal_commit,
        .next_leaf = journal_next_leaf,
        .bound_key = journal_bound_key,
        .bind_key = journal_bind_key,
    };
    uint8_t identity[PQHS_KEY_IDENTITY_LEN];
    int failures = 0;
    journal_reset();
    failures += expect_rc("key_identity", pqhs_key_identity(suite, pk, pk_len, identity,
                                                            sizeof(identity)),
                          PQHS_OK);
    failures += expect_rc("adopt_key", pqhs_adopt_key(&journal, identity, sizeof(identity)),
                          PQHS_OK);
    return failures;
}

/* Reports failure without recording anything, as the contract requires. */
static int journal_refuse_commit(void *ctx, uint32_t leaf) {
    (void)ctx;
    (void)leaf;
    g_commit_calls += 1;
    return 1;
}

/* ------------------------------------------------------------------ */
/* H5: stateful sign and verify                                        */
/* ------------------------------------------------------------------ */

static int check_h5(void) {
    size_t sk_len, pk_len, sig_max_len;
    if (pqhs_secret_key_len(5, &sk_len) != PQHS_OK) return fail("h5 secret_key_len", 1);
    if (pqhs_public_key_len(5, &pk_len) != PQHS_OK) return fail("h5 public_key_len", 1);
    if (pqhs_signature_len(5, &sig_max_len) != PQHS_OK) return fail("h5 signature_len", 1);

    int failures = 0;
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sk_out = calloc(1, sk_len);
    uint8_t *sig = calloc(1, sig_max_len);
    if (!sk || !pk || !sk_out || !sig) {
        fprintf(stderr, "FAIL: h5 allocation\n");
        failures = 1;
        goto done;
    }

    uint8_t seed[32];
    memset(seed, 0x99, sizeof(seed));

    int rc = pqhs_keygen_stateful_from_seed(5, seed, sizeof(seed), 4, sk, sk_len, pk, pk_len);
    if (rc != PQHS_OK) {
        failures = fail("h5 keygen_stateful_from_seed", rc);
        goto done;
    }
    failures += journal_provision(5, pk, pk_len);

    PqhsLeafJournal journal = {
        .ctx = NULL,
        .commit = journal_commit,
        .next_leaf = journal_next_leaf,
        .bound_key = journal_bound_key,
        .bind_key = journal_bind_key,
    };

    const uint8_t msg[] = "a stateful message";
    size_t sig_len = 0;
    rc = pqhs_sign_stateful(5, sk, sk_len, &journal, msg, sizeof(msg), NULL, 0, sk_out, sk_len,
                             sig, sig_max_len, &sig_len);
    if (rc != PQHS_OK) {
        failures = fail("h5 sign_stateful", rc);
        goto done;
    }
    failures += expect_true("h5 exported key advanced past the spent leaf",
                            memcmp(sk, sk_out, sk_len) != 0);

    bool valid = false;
    rc = pqhs_verify(5, pk, pk_len, msg, sizeof(msg), NULL, 0, sig, sig_len, &valid);
    failures += expect_rc("h5 verify call", rc, PQHS_OK);
    failures += expect_true("h5 stateful signature verified", valid);

    /* pqhs_stored_public_key_len and pqhs_verify_with_stored_public_key,
     * against the same key and signature check_h5 already built: `pk` is
     * `ClassicalPK || PqVerifyKey` (see pqhs_public_key_len); the stored
     * form is `ClassicalPK || commitment`, where the 32-byte commitment
     * sits at a fixed offset (68) inside the bundle that follows the
     * classical prefix -- the SHRINCS `statefulPublicKey(68) ||
     * commitment(32) || pkSeed || hypertreeRoot` layout, the same one
     * pqhybridsign-abi's own stateful_suites tests use. */
    size_t stored_len = 0;
    rc = pqhs_stored_public_key_len(5, &stored_len);
    if (rc != PQHS_OK) {
        failures += fail("h5 stored_public_key_len", rc);
        goto done;
    }
    size_t classical_len = stored_len - 32;
    size_t bundle_len = pk_len - classical_len;
    uint8_t *stored = calloc(1, stored_len);
    if (!stored) {
        fprintf(stderr, "FAIL: h5 stored allocation\n");
        failures = 1;
        goto done;
    }
    memcpy(stored, pk, classical_len);
    memcpy(stored + classical_len, pk + classical_len + 68, 32);
    const uint8_t *bundle = pk + classical_len;

    bool stored_valid = false;
    rc = pqhs_verify_with_stored_public_key(5, stored, stored_len, bundle, bundle_len, msg,
                                             sizeof(msg), NULL, 0, sig, sig_len, &stored_valid);
    failures += expect_rc("h5 verify_with_stored_public_key call", rc, PQHS_OK);
    failures += expect_true("h5 stateful signature verified against its stored form",
                            stored_valid);
    free(stored);

done:
    free(sk);
    free(pk);
    free(sk_out);
    free(sig);
    return failures;
}

/* ------------------------------------------------------------------ */
/* Error cases on the stateless entry points                           */
/* ------------------------------------------------------------------ */

static int check_stateless_error_cases(void) {
    size_t sk_len, pk_len, sig_max_len;
    if (pqhs_secret_key_len(1, &sk_len) != PQHS_OK) return fail("h1 secret_key_len", 1);
    if (pqhs_public_key_len(1, &pk_len) != PQHS_OK) return fail("h1 public_key_len", 1);
    if (pqhs_signature_len(1, &sig_max_len) != PQHS_OK) return fail("h1 signature_len", 1);

    int failures = 0;
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sig = calloc(1, sig_max_len);
    if (!sk || !pk || !sig) {
        fprintf(stderr, "FAIL: stateless error-case allocation\n");
        failures = 1;
        goto done;
    }

    uint8_t seed[32];
    memset(seed, 0x11, sizeof(seed));
    int rc = pqhs_keygen_from_seed(1, seed, sizeof(seed), sk, sk_len, pk, pk_len);
    if (rc != PQHS_OK) {
        failures = fail("stateless error-case keygen", rc);
        goto done;
    }

    const uint8_t msg[] = "m";
    size_t sig_len = 0;

    /* A keygen output buffer of the wrong length, short and long. Both are
     * exact-length parameters, so an oversized buffer is as wrong as a
     * short one -- a caller who sizes from a different suite gets told. */
    rc = pqhs_keygen_from_seed(1, seed, sizeof(seed), sk, sk_len - 1, pk, pk_len);
    failures += expect_rc("short sk_out rejected", rc, PQHS_ERR_BAD_LENGTH);
    rc = pqhs_keygen_from_seed(1, seed, sizeof(seed), sk, sk_len, pk, pk_len - 1);
    failures += expect_rc("short pk_out rejected", rc, PQHS_ERR_BAD_LENGTH);

    /* The oversized case needs a buffer that really is that long, since the
     * length is what the library is told to write through. */
    uint8_t *sk_long = calloc(1, sk_len + 1);
    if (!sk_long) {
        fprintf(stderr, "FAIL: oversized-buffer allocation\n");
        failures += 1;
        goto done;
    }
    rc = pqhs_keygen_from_seed(1, seed, sizeof(seed), sk_long, sk_len + 1, pk, pk_len);
    failures += expect_rc("oversized sk_out rejected", rc, PQHS_ERR_BAD_LENGTH);
    free(sk_long);

    /* A short signature buffer. */
    rc = pqhs_sign(1, sk, sk_len, msg, sizeof(msg), NULL, 0, sig, 1, &sig_len);
    failures += expect_true("short sig_out rejected", rc != PQHS_OK);

    /* A null sig_written, on a call that would otherwise succeed. The
     * signature must not be produced: an error code here used to arrive
     * after the work was done, which invites the caller to sign again. */
    memset(sig, 0, sig_max_len);
    rc = pqhs_sign(1, sk, sk_len, msg, sizeof(msg), NULL, 0, sig, sig_max_len, NULL);
    failures += expect_rc("null sig_written rejected", rc, PQHS_ERR_NULL_POINTER);
    int untouched = 1;
    for (size_t i = 0; i < sig_max_len; i++) {
        if (sig[i] != 0) {
            untouched = 0;
            break;
        }
    }
    failures += expect_true("null sig_written left sig_out untouched", untouched);

    rc = pqhs_sign_deterministic(1, sk, sk_len, msg, sizeof(msg), NULL, 0, NULL, 0, sig,
                                  sig_max_len, NULL);
    failures += expect_rc("null sig_written rejected (deterministic)", rc, PQHS_ERR_NULL_POINTER);

    /* The wrong entry point for the suite, in both directions. */
    rc = pqhs_sign(5, sk, sk_len, msg, sizeof(msg), NULL, 0, sig, sig_max_len, &sig_len);
    failures += expect_rc("pqhs_sign rejects H5", rc, PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);
    rc = pqhs_keygen_from_seed(5, seed, sizeof(seed), sk, sk_len, pk, pk_len);
    failures += expect_rc("pqhs_keygen_from_seed rejects H5", rc,
                          PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);
    rc = pqhs_keygen_stateful_from_seed(1, seed, sizeof(seed), 4, sk, sk_len, pk, pk_len);
    failures += expect_rc("pqhs_keygen_stateful_from_seed rejects H1", rc,
                          PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);

    /* An unknown suite code. */
    rc = pqhs_sign(99, sk, sk_len, msg, sizeof(msg), NULL, 0, sig, sig_max_len, &sig_len);
    failures += expect_rc("unknown suite rejected", rc, PQHS_ERR_INVALID_SUITE);

done:
    free(sk);
    free(pk);
    free(sig);
    return failures;
}

/* ------------------------------------------------------------------ */
/* Error cases on the stateful entry points                            */
/* ------------------------------------------------------------------ */

static int check_stateful_error_cases(void) {
    size_t sk_len, pk_len, sig_max_len;
    if (pqhs_secret_key_len(5, &sk_len) != PQHS_OK) return fail("h5 secret_key_len", 1);
    if (pqhs_public_key_len(5, &pk_len) != PQHS_OK) return fail("h5 public_key_len", 1);
    if (pqhs_signature_len(5, &sig_max_len) != PQHS_OK) return fail("h5 signature_len", 1);

    int failures = 0;
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sk_out = calloc(1, sk_len);
    uint8_t *sig = calloc(1, sig_max_len);
    if (!sk || !pk || !sk_out || !sig) {
        fprintf(stderr, "FAIL: stateful error-case allocation\n");
        failures = 1;
        goto done;
    }

    uint8_t seed[32];
    memset(seed, 0x5a, sizeof(seed));

    /* A budget of one leaf, so the budget can be exhausted cheaply. */
    int rc = pqhs_keygen_stateful_from_seed(5, seed, sizeof(seed), 1, sk, sk_len, pk, pk_len);
    if (rc != PQHS_OK) {
        failures = fail("stateful error-case keygen", rc);
        goto done;
    }
    failures += journal_provision(5, pk, pk_len);
    budget_reset();
    PqhsStatelessBudget budget = make_budget();

    PqhsLeafJournal journal = {
        .ctx = NULL,
        .commit = journal_commit,
        .next_leaf = journal_next_leaf,
        .bound_key = journal_bound_key,
        .bind_key = journal_bind_key,
    };
    const uint8_t msg[] = "m";
    size_t sig_len = 0;

    /* --- A wrong-length sk_out must not spend a leaf. ---
     *
     * This is the case that used to brick the key: the length was checked
     * after the signer had committed a leaf, so the journal advanced and
     * the caller never got the advanced key back. */
    rc = pqhs_sign_stateful(5, sk, sk_len, &journal, msg, sizeof(msg), NULL, 0, sk_out,
                             sk_len - 1, sig, sig_max_len, &sig_len);
    failures += expect_rc("short sk_out rejected", rc, PQHS_ERR_BAD_LENGTH);
    failures += expect_true("short sk_out spent no leaf", g_commit_calls == 0);

    /* The oversized case needs a buffer that really is that long: the
     * length is what the library is told to write through, so handing it a
     * length past the end of the allocation would be the test's own bug. */
    uint8_t *sk_out_long = calloc(1, sk_len + 1);
    if (!sk_out_long) {
        fprintf(stderr, "FAIL: oversized-buffer allocation\n");
        failures += 1;
        goto done;
    }
    rc = pqhs_sign_stateful(5, sk, sk_len, &journal, msg, sizeof(msg), NULL, 0, sk_out_long,
                             sk_len + 1, sig, sig_max_len, &sig_len);
    failures += expect_rc("oversized sk_out rejected", rc, PQHS_ERR_BAD_LENGTH);
    failures += expect_true("oversized sk_out spent no leaf", g_commit_calls == 0);
    free(sk_out_long);

    rc = pqhs_sign_stateful(5, sk, sk_len - 1, &journal, msg, sizeof(msg), NULL, 0, sk_out,
                             sk_len, sig, sig_max_len, &sig_len);
    failures += expect_rc("short sk rejected", rc, PQHS_ERR_BAD_LENGTH);
    failures += expect_true("short sk spent no leaf", g_commit_calls == 0);

    /* --- A null sig_written must not spend a leaf. --- */
    rc = pqhs_sign_stateful(5, sk, sk_len, &journal, msg, sizeof(msg), NULL, 0, sk_out, sk_len,
                             sig, sig_max_len, NULL);
    failures += expect_rc("null sig_written rejected", rc, PQHS_ERR_NULL_POINTER);
    failures += expect_true("null sig_written spent no leaf", g_commit_calls == 0);

    /* --- An aliased sk/sk_out pair must be refused, not silently work. ---
     *
     * Passing one buffer as both is the most natural way to write an
     * in-place key update in C, and it is undefined behaviour. */
    rc = pqhs_sign_stateful(5, sk, sk_len, &journal, msg, sizeof(msg), NULL, 0, sk, sk_len, sig,
                             sig_max_len, &sig_len);
    failures += expect_rc("aliased sk/sk_out rejected", rc, PQHS_ERR_ALIASED_BUFFERS);
    failures += expect_true("aliased sk/sk_out spent no leaf", g_commit_calls == 0);

    /* Partial overlap is the same defect and the likelier accident. */
    rc = pqhs_sign_stateful(5, sk, sk_len, &journal, msg, sizeof(msg), NULL, 0, sk + sk_len / 2,
                             sk_len / 2, sig, sig_max_len, &sig_len);
    failures += expect_true("partially aliased sk/sk_out rejected", rc != PQHS_OK);
    failures += expect_true("partially aliased sk/sk_out spent no leaf", g_commit_calls == 0);

    /* --- The wrong entry point for the suite. --- */
    rc = pqhs_sign_stateful(1, sk, sk_len, &journal, msg, sizeof(msg), NULL, 0, sk_out, sk_len,
                             sig, sig_max_len, &sig_len);
    failures += expect_rc("pqhs_sign_stateful rejects H1", rc,
                          PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);
    rc = pqhs_sign_stateless(1, sk, sk_len, &budget, msg, sizeof(msg), NULL, 0, sig, sig_max_len,
                              &sig_len);
    failures += expect_rc("pqhs_sign_stateless rejects H1", rc,
                          PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);

    /* --- A null journal, and a journal with a null callback. --- */
    rc = pqhs_sign_stateful(5, sk, sk_len, NULL, msg, sizeof(msg), NULL, 0, sk_out, sk_len, sig,
                             sig_max_len, &sig_len);
    failures += expect_rc("null journal rejected", rc, PQHS_ERR_NULL_POINTER);

    PqhsLeafJournal no_commit = {.ctx = NULL,
                                 .commit = NULL,
                                 .next_leaf = journal_next_leaf,
                                 .bound_key = journal_bound_key,
                                 .bind_key = journal_bind_key};
    rc = pqhs_sign_stateful(5, sk, sk_len, &no_commit, msg, sizeof(msg), NULL, 0, sk_out, sk_len,
                             sig, sig_max_len, &sig_len);
    failures += expect_rc("null commit callback rejected", rc, PQHS_ERR_NULL_POINTER);

    PqhsLeafJournal no_next = {.ctx = NULL,
                               .commit = journal_commit,
                               .next_leaf = NULL,
                               .bound_key = journal_bound_key,
                               .bind_key = journal_bind_key};

    PqhsLeafJournal no_bound_key = {.ctx = NULL,
                                    .commit = journal_commit,
                                    .next_leaf = journal_next_leaf,
                                    .bound_key = NULL,
                                    .bind_key = journal_bind_key};
    rc = pqhs_sign_stateful(5, sk, sk_len, &no_bound_key, msg, sizeof(msg), NULL, 0, sk_out,
                             sk_len, sig, sig_max_len, &sig_len);
    failures += expect_rc("null bound_key callback rejected", rc, PQHS_ERR_NULL_POINTER);

    PqhsLeafJournal no_bind_key = {.ctx = NULL,
                                   .commit = journal_commit,
                                   .next_leaf = journal_next_leaf,
                                   .bound_key = journal_bound_key,
                                   .bind_key = NULL};
    rc = pqhs_sign_stateful(5, sk, sk_len, &no_bind_key, msg, sizeof(msg), NULL, 0, sk_out,
                             sk_len, sig, sig_max_len, &sig_len);
    failures += expect_rc("null bind_key callback rejected", rc, PQHS_ERR_NULL_POINTER);
    rc = pqhs_sign_stateful(5, sk, sk_len, &no_next, msg, sizeof(msg), NULL, 0, sk_out, sk_len,
                             sig, sig_max_len, &sig_len);
    failures += expect_rc("null next_leaf callback rejected", rc, PQHS_ERR_NULL_POINTER);
    failures += expect_true("no rejected call spent a leaf", g_commit_calls == 0);

    /* --- A journal that refuses to commit spends nothing. --- */
    PqhsLeafJournal refusing = {
        .ctx = NULL,
        .commit = journal_refuse_commit,
        .next_leaf = journal_next_leaf,
        .bound_key = journal_bound_key,
        .bind_key = journal_bind_key,
    };
    rc = pqhs_sign_stateful(5, sk, sk_len, &refusing, msg, sizeof(msg), NULL, 0, sk_out, sk_len,
                             sig, sig_max_len, &sig_len);
    failures += expect_rc("refusing journal reports JOURNAL_FAILED", rc, PQHS_ERR_JOURNAL_FAILED);
    failures += expect_true("refusing journal recorded nothing", !g_have_committed);

    /* --- The key still signs, and then its budget is exhausted. ---
     *
     * Every call above reported an error; if any of them had quietly spent
     * the single leaf this key was given, this call would fail. */
    failures += journal_provision(5, pk, pk_len);
    rc = pqhs_sign_stateful(5, sk, sk_len, &journal, msg, sizeof(msg), NULL, 0, sk_out, sk_len,
                             sig, sig_max_len, &sig_len);
    failures += expect_rc("the key still signs after every rejected call", rc, PQHS_OK);

    bool valid = false;
    rc = pqhs_verify(5, pk, pk_len, msg, sizeof(msg), NULL, 0, sig, sig_len, &valid);
    failures += expect_rc("verify call after the surviving signature", rc, PQHS_OK);
    failures += expect_true("the surviving signature verifies", valid);

    /* The budget was one leaf and it is now spent. Signing again with the
     * advanced key must say so, rather than reissuing the leaf. */
    uint8_t *sk_out2 = calloc(1, sk_len);
    if (!sk_out2) {
        fprintf(stderr, "FAIL: exhausted-budget allocation\n");
        failures += 1;
        goto done;
    }
    rc = pqhs_sign_stateful(5, sk_out, sk_len, &journal, msg, sizeof(msg), NULL, 0, sk_out2,
                             sk_len, sig, sig_max_len, &sig_len);
    failures += expect_rc("an exhausted leaf budget is reported", rc, PQHS_ERR_LEAVES_EXHAUSTED);
    free(sk_out2);

    /* --- The stateless few-time path spends no leaf, but does spend
     * budget: it draws on its own bound, which is shared with rotation and
     * recovery. --- */
    failures += expect_true("stateless path starts with nothing on record",
                            g_have_budget_entry == 0);
    rc = pqhs_sign_stateless(5, sk, sk_len, &budget, msg, sizeof(msg), NULL, 0, sig, sig_max_len,
                              &sig_len);
    failures += expect_rc("stateless path signs", rc, PQHS_OK);
    failures += expect_true("stateless path charged one unit",
                            g_have_budget_entry && g_budget_count == 1);
    rc = pqhs_sign_stateless(5, sk, sk_len, &budget, msg, sizeof(msg), NULL, 0, sig, sig_max_len,
                              &sig_len);
    failures += expect_rc("stateless path repeats", rc, PQHS_OK);
    failures += expect_true("stateless path charged a second unit", g_budget_count == 2);

    /* A store that cannot make the spend durable must refuse the signature
     * and leave the count where it was: a signature released against a
     * spend a restart forgets is a signature the bound never saw. */
    g_budget_record_fails = 1;
    rc = pqhs_sign_stateless(5, sk, sk_len, &budget, msg, sizeof(msg), NULL, 0, sig, sig_max_len,
                              &sig_len);
    failures += expect_rc("a failed budget record refuses the signature", rc,
                          PQHS_ERR_BUDGET_STORE_FAILED);
    failures += expect_true("a failed budget record spends nothing", g_budget_count == 2);
    g_budget_record_fails = 0;

    /* A null budget, and a budget with a null callback: both are refused
     * before anything is read or charged, and neither is reported as a
     * storage fault, which would send an integrator to look at their disk
     * for a vtable they never filled in. */
    rc = pqhs_sign_stateless(5, sk, sk_len, NULL, msg, sizeof(msg), NULL, 0, sig, sig_max_len,
                              &sig_len);
    failures += expect_rc("null budget rejected", rc, PQHS_ERR_NULL_POINTER);
    PqhsStatelessBudget no_record = {
        .ctx = NULL, .consumed = budget_consumed, .record = NULL};
    rc = pqhs_sign_stateless(5, sk, sk_len, &no_record, msg, sizeof(msg), NULL, 0, sig,
                              sig_max_len, &sig_len);
    failures += expect_rc("budget with a null record callback rejected", rc,
                          PQHS_ERR_NULL_POINTER);
    PqhsStatelessBudget no_consumed = {.ctx = NULL, .consumed = NULL, .record = budget_record};
    rc = pqhs_sign_stateless(5, sk, sk_len, &no_consumed, msg, sizeof(msg), NULL, 0, sig,
                              sig_max_len, &sig_len);
    failures += expect_rc("budget with a null consumed callback rejected", rc,
                          PQHS_ERR_NULL_POINTER);
    failures += expect_true("a rejected vtable never reached the store",
                            g_budget_count == 2);
    rc = pqhs_sign_stateless(5, sk, sk_len, &budget, msg, sizeof(msg), NULL, 0, sig, 1, &sig_len);
    failures += expect_true("stateless path rejects a short sig_out", rc != PQHS_OK);
    rc = pqhs_sign_stateless(5, sk, sk_len, &budget, msg, sizeof(msg), NULL, 0, sig, sig_max_len, NULL);
    failures += expect_rc("stateless path rejects a null sig_written", rc,
                          PQHS_ERR_NULL_POINTER);

done:
    free(sk);
    free(pk);
    free(sk_out);
    free(sig);
    return failures;
}

/* ------------------------------------------------------------------ */
/* A journal must belong to the key it spends for                      */
/* ------------------------------------------------------------------ */

/* One key blob, two journals that have each recorded nothing. Both report
 * leaf 0, truthfully, so no counter check can separate a journal correctly
 * reopened for its own key from a brand-new one handed the same key by
 * mistake. Only the binding can, and signing under an unbound journal is
 * refused with PQHS_ERR_JOURNAL_KEY_MISMATCH before anything is spent.
 *
 * Every leaf index here is signer-side and zero-based, not the one-based
 * LeafCount a signature carries on the wire. */
static int check_journal_key_binding(void) {
    size_t sk_len, pk_len, sig_max_len;
    if (pqhs_secret_key_len(5, &sk_len) != PQHS_OK) return fail("binding secret_key_len", 1);
    if (pqhs_public_key_len(5, &pk_len) != PQHS_OK) return fail("binding public_key_len", 1);
    if (pqhs_signature_len(5, &sig_max_len) != PQHS_OK) return fail("binding signature_len", 1);

    int failures = 0;
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *pk = calloc(1, pk_len);
    uint8_t *other_pk = calloc(1, pk_len);
    uint8_t *other_sk = calloc(1, sk_len);
    uint8_t *sk_out = calloc(1, sk_len);
    uint8_t *sig = calloc(1, sig_max_len);
    if (!sk || !pk || !other_pk || !other_sk || !sk_out || !sig) {
        fprintf(stderr, "FAIL: binding allocation\n");
        failures = 1;
        goto done;
    }

    uint8_t seed[32];
    memset(seed, 0x71, sizeof(seed));
    int rc = pqhs_keygen_stateful_from_seed(5, seed, sizeof(seed), 4, sk, sk_len, pk, pk_len);
    if (rc != PQHS_OK) {
        failures = fail("binding keygen", rc);
        goto done;
    }
    failures += journal_provision(5, pk, pk_len);

    PqhsLeafJournal journal = {
        .ctx = NULL,
        .commit = journal_commit,
        .next_leaf = journal_next_leaf,
        .bound_key = journal_bound_key,
        .bind_key = journal_bind_key,
    };

    /* The key's own journal signs. */
    const uint8_t msg[] = "message one";
    size_t sig_len = 0;
    rc = pqhs_sign_stateful(5, sk, sk_len, &journal, msg, sizeof(msg), NULL, 0, sk_out, sk_len,
                             sig, sig_max_len, &sig_len);
    failures += expect_rc("the key's own journal signs", rc, PQHS_OK);
    failures += expect_true("the first signature spent leaf 0",
                            g_have_committed && g_committed_leaf == 0);

    /* A second store: never committed anything, never bound to any key. Its
     * counter agrees with the key's, which is the whole difficulty. */
    journal_reset();
    failures += expect_true("the fresh journal reports leaf 0", journal_next_leaf(NULL) == 0);
    const uint8_t msg_two[] = "message two";
    rc = pqhs_sign_stateful(5, sk, sk_len, &journal, msg_two, sizeof(msg_two), NULL, 0, sk_out,
                             sk_len, sig, sig_max_len, &sig_len);
    failures += expect_rc("an unbound journal cannot spend this key's leaves", rc,
                          PQHS_ERR_JOURNAL_KEY_MISMATCH);
    failures += expect_true("the refusal spent nothing", g_commit_calls == 0);

    /* A journal bound to a different key is refused on the same terms. */
    memset(seed, 0x72, sizeof(seed));
    rc = pqhs_keygen_stateful_from_seed(5, seed, sizeof(seed), 4, other_sk, sk_len, other_pk,
                                        pk_len);
    failures += expect_rc("second keygen", rc, PQHS_OK);
    failures += journal_provision(5, other_pk, pk_len);
    rc = pqhs_sign_stateful(5, sk, sk_len, &journal, msg, sizeof(msg), NULL, 0, sk_out, sk_len,
                             sig, sig_max_len, &sig_len);
    failures += expect_rc("another key's journal is refused", rc,
                          PQHS_ERR_JOURNAL_KEY_MISMATCH);
    failures += expect_true("that refusal spent nothing too", g_commit_calls == 0);

    /* Adopting a second key over an existing binding is refused, and the
     * existing binding stands. */
    uint8_t identity[PQHS_KEY_IDENTITY_LEN];
    rc = pqhs_key_identity(5, pk, pk_len, identity, sizeof(identity));
    failures += expect_rc("key_identity for the first key", rc, PQHS_OK);
    rc = pqhs_adopt_key(&journal, identity, sizeof(identity));
    failures += expect_rc("a journal belongs to one key", rc, PQHS_ERR_JOURNAL_KEY_MISMATCH);

    /* The public key and the secret key blob name the same identity. */
    uint8_t from_sk[PQHS_KEY_IDENTITY_LEN];
    rc = pqhs_key_identity_from_secret_key(5, sk, sk_len, from_sk, sizeof(from_sk));
    failures += expect_rc("key_identity_from_secret_key", rc, PQHS_OK);
    failures += expect_true("public and secret name the same key",
                            memcmp(identity, from_sk, sizeof(identity)) == 0);

    /* And two keys do not share an identity. */
    uint8_t other_identity[PQHS_KEY_IDENTITY_LEN];
    rc = pqhs_key_identity(5, other_pk, pk_len, other_identity, sizeof(other_identity));
    failures += expect_rc("key_identity for the second key", rc, PQHS_OK);
    failures += expect_true("two keys have two identities",
                            memcmp(identity, other_identity, sizeof(identity)) != 0);

done:
    free(sk);
    free(pk);
    free(other_pk);
    free(other_sk);
    free(sk_out);
    free(sig);
    return failures;
}

/* ------------------------------------------------------------------ */
/* Malformed verify input                                              */
/* ------------------------------------------------------------------ */

/* pqhs_verify promises never to error and never to crash on a malformed pk
 * or sig: it reports `false` and PQHS_OK, so that a caller cannot learn
 * which component or encoding rejected from the error code. Nothing
 * exercised that promise against a non-null pointer of the wrong length,
 * which is exactly the shape attacker-supplied bytes arrive in. */
static int check_malformed_verify_input(void) {
    size_t pk_len, sig_max_len;
    if (pqhs_public_key_len(1, &pk_len) != PQHS_OK) return fail("h1 public_key_len", 1);
    if (pqhs_signature_len(1, &sig_max_len) != PQHS_OK) return fail("h1 signature_len", 1);

    int failures = 0;

    /* The scratch buffers must cover every length this function hands to
     * pqhs_verify, including the largest signature any of the six suites
     * can produce -- a length past the end of the allocation would be the
     * test's own out-of-bounds read, not the library's. */
    size_t scratch_len = 4096;
    for (uint8_t suite = 1; suite <= 6; suite++) {
        size_t n = 0;
        if (pqhs_public_key_len(suite, &n) == PQHS_OK && n + 1 > scratch_len) scratch_len = n + 1;
        if (pqhs_signature_len(suite, &n) == PQHS_OK && n + 1 > scratch_len) scratch_len = n + 1;
    }

    uint8_t *zeros = calloc(1, scratch_len);
    uint8_t *ones = calloc(1, scratch_len);
    if (!zeros || !ones) {
        fprintf(stderr, "FAIL: malformed-verify allocation\n");
        failures = 1;
        goto done;
    }
    memset(ones, 0xff, scratch_len);

    const uint8_t msg[] = "m";
    /* Lengths that are wrong in every direction: empty, a single byte, one
     * byte short of correct, one byte long, and far too long. */
    const size_t lengths[] = {0, 1, 4, pk_len - 1, pk_len + 1, scratch_len};
    const size_t length_count = sizeof(lengths) / sizeof(lengths[0]);

    for (size_t suite = 1; suite <= 6; suite++) {
        for (size_t i = 0; i < length_count; i++) {
            for (int use_ones = 0; use_ones <= 1; use_ones++) {
                const uint8_t *buf = use_ones ? ones : zeros;
                char what[128];

                /* A malformed public key against a right-shaped signature
                 * buffer. */
                bool valid = true;
                int rc = pqhs_verify((uint8_t)suite, buf, lengths[i], msg, sizeof(msg), NULL, 0,
                                      zeros, sig_max_len, &valid);
                snprintf(what, sizeof(what), "malformed pk (suite %zu, len %zu, %s)", suite,
                         lengths[i], use_ones ? "0xff" : "0x00");
                failures += expect_rc(what, rc, PQHS_OK);
                failures += expect_true(what, !valid);

                /* A malformed signature against a right-shaped public key
                 * buffer. */
                valid = true;
                rc = pqhs_verify((uint8_t)suite, zeros, pk_len, msg, sizeof(msg), NULL, 0, buf,
                                  lengths[i], &valid);
                snprintf(what, sizeof(what), "malformed sig (suite %zu, len %zu, %s)", suite,
                         lengths[i], use_ones ? "0xff" : "0x00");
                failures += expect_rc(what, rc, PQHS_OK);
                failures += expect_true(what, !valid);
            }
        }
    }

    /* A truncated but otherwise genuine signature must also fail closed. */
    {
        size_t sk_len;
        if (pqhs_secret_key_len(1, &sk_len) != PQHS_OK) {
            failures += fail("h1 secret_key_len", 1);
            goto done;
        }
        uint8_t *sk = calloc(1, sk_len);
        uint8_t *pk = calloc(1, pk_len);
        uint8_t *sig = calloc(1, sig_max_len);
        if (!sk || !pk || !sig) {
            fprintf(stderr, "FAIL: truncated-signature allocation\n");
            failures += 1;
            free(sk);
            free(pk);
            free(sig);
            goto done;
        }
        uint8_t seed[32];
        memset(seed, 0x77, sizeof(seed));
        size_t sig_len = 0;
        int rc = pqhs_keygen_from_seed(1, seed, sizeof(seed), sk, sk_len, pk, pk_len);
        if (rc == PQHS_OK) {
            rc = pqhs_sign_deterministic(1, sk, sk_len, msg, sizeof(msg), NULL, 0, NULL, 0, sig,
                                          sig_max_len, &sig_len);
        }
        if (rc != PQHS_OK) {
            failures += fail("truncated-signature setup", rc);
        } else {
            bool valid = true;
            rc = pqhs_verify(1, pk, pk_len, msg, sizeof(msg), NULL, 0, sig, sig_len - 1, &valid);
            failures += expect_rc("truncated signature", rc, PQHS_OK);
            failures += expect_true("truncated signature rejected", !valid);

            valid = true;
            rc = pqhs_verify(1, pk, pk_len - 1, msg, sizeof(msg), NULL, 0, sig, sig_len, &valid);
            failures += expect_rc("truncated public key", rc, PQHS_OK);
            failures += expect_true("truncated public key rejected", !valid);
        }
        free(sk);
        free(pk);
        free(sig);
    }

done:
    free(zeros);
    free(ones);
    return failures;
}

/* ------------------------------------------------------------------ */
/* Null pointers, fail-closed verify, and the profile string           */
/* ------------------------------------------------------------------ */

static int check_null_pointer_and_profile(void) {
    int failures = 0;

    /* A null pk paired with a nonzero length is a null-pointer error, never
     * a dereference -- and valid_out must still be written `false`, so that
     * a caller who ignores the return code fails closed. */
    bool valid = true;
    int rc = pqhs_verify(1, NULL, 64, (const uint8_t *)"m", 1, NULL, 0, (const uint8_t *)"s", 1,
                          &valid);
    failures += expect_rc("null pk rejected", rc, PQHS_ERR_NULL_POINTER);
    failures += expect_true("null pk left valid_out false", !valid);

    /* An unknown suite likewise. */
    valid = true;
    rc = pqhs_verify(99, (const uint8_t *)"p", 1, (const uint8_t *)"m", 1, NULL, 0,
                      (const uint8_t *)"s", 1, &valid);
    failures += expect_rc("unknown suite rejected by verify", rc, PQHS_ERR_INVALID_SUITE);
    failures += expect_true("unknown suite left valid_out false", !valid);

    /* A null valid_out is the one case that cannot fail closed. */
    rc = pqhs_verify(1, (const uint8_t *)"p", 1, (const uint8_t *)"m", 1, NULL, 0,
                      (const uint8_t *)"s", 1, NULL);
    failures += expect_rc("null valid_out rejected", rc, PQHS_ERR_NULL_POINTER);

    /* A null out-parameter on the size queries. */
    rc = pqhs_secret_key_len(1, NULL);
    failures += expect_rc("null size out-parameter rejected", rc, PQHS_ERR_NULL_POINTER);

    const char *profile = pqhs_profile_name();
    if (!profile || strncmp(profile, "shrincs-", 8) != 0) {
        fprintf(stderr, "FAIL: unexpected profile name: %s\n", profile ? profile : "(null)");
        failures += 1;
    }
    return failures;
}

int main(void) {
    int failures = 0;
    failures += check_h1();
    failures += check_h5();
    failures += check_stateless_error_cases();
    failures += check_stateful_error_cases();
    failures += check_journal_key_binding();
    failures += check_malformed_verify_input();
    failures += check_null_pointer_and_profile();

    if (failures == 0) {
        printf("OK: all C ABI checks passed\n");
        return 0;
    }
    fprintf(stderr, "%d C ABI check(s) failed\n", failures);
    return 1;
}

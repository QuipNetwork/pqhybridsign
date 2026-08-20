/* SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Sign/verify roundtrip example for H1 through H4, built against the
 * pqhybridsign C ABI (crates/pqhybridsign-cffi/include/pqhybridsign.h).
 *
 * For each suite: derive a keypair from a fixed seed, sign a message
 * deterministically, verify the signature, tamper one message byte, and
 * confirm verification then fails. Every seed and nonce is a fixed
 * constant, so the run needs no random number generator and is
 * byte-for-byte repeatable.
 *
 * Prints one line per suite checked and exits 0. On the first failure it
 * prints a message to stderr and exits nonzero.
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "pqhybridsign.h"

namespace {

/* Application context bound into every signature. */
const uint8_t kCtx[] = "pqhybridsign-example-ctx";
/* Fixed nonce for deterministic signing. Not every component honours it
 * (see pqhs_sign_deterministic's documentation), but it removes any
 * dependency on a random number generator for this example. */
const uint8_t kNonce[] = "pqhybridsign-example-nonce";
/* Message signed by every suite in this example. */
const uint8_t kMessage[] = "pqhybridsign roundtrip message";

/* Reports `what` and the pqhybridsign error message for `rc`, then
 * returns false so the caller can propagate failure. */
bool Fail(const char *what, int rc) {
  std::fprintf(stderr, "error: %s: %s (rc=%d)\n", what, pqhs_error_message(rc), rc);
  return false;
}

/* Reports `what` as a plain failure with no error code, then returns
 * false so the caller can propagate failure. */
bool FailMsg(const char *what) {
  std::fprintf(stderr, "error: %s\n", what);
  return false;
}

/* Roundtrip one stateless suite: keygen, sign, verify true, tamper,
 * verify false. Returns true and prints one line on success, or reports
 * to stderr and returns false on the first failure. */
bool CheckSuite(uint8_t suite, const char *name) {
  size_t sk_len = 0, pk_len = 0, sig_max_len = 0;
  int rc = pqhs_secret_key_len(suite, &sk_len);
  if (rc != PQHS_OK) return Fail("secret_key_len", rc);
  rc = pqhs_public_key_len(suite, &pk_len);
  if (rc != PQHS_OK) return Fail("public_key_len", rc);
  rc = pqhs_signature_len(suite, &sig_max_len);
  if (rc != PQHS_OK) return Fail("signature_len", rc);

  std::vector<uint8_t> sk(sk_len, 0);
  std::vector<uint8_t> pk(pk_len, 0);
  std::vector<uint8_t> sig(sig_max_len, 0);

  /* One fixed 32-byte master seed per suite, so a suite's keypair never
   * depends on another suite's. */
  uint8_t seed[32];
  std::memset(seed, static_cast<int>(suite), sizeof(seed));

  rc = pqhs_keygen_from_seed(suite, seed, sizeof(seed), sk.data(), sk.size(), pk.data(),
                              pk.size());
  if (rc != PQHS_OK) return Fail("keygen_from_seed", rc);

  size_t sig_len = 0;
  rc = pqhs_sign_deterministic(suite, sk.data(), sk.size(), kMessage, sizeof(kMessage), kCtx,
                                sizeof(kCtx), kNonce, sizeof(kNonce), sig.data(), sig.size(),
                                &sig_len);
  if (rc != PQHS_OK) return Fail("sign_deterministic", rc);

  bool valid = false;
  rc = pqhs_verify(suite, pk.data(), pk.size(), kMessage, sizeof(kMessage), kCtx, sizeof(kCtx),
                    sig.data(), sig_len, &valid);
  if (rc != PQHS_OK) return Fail("verify", rc);
  if (!valid) return FailMsg("verify of the untampered signature returned false");

  std::vector<uint8_t> tampered(kMessage, kMessage + sizeof(kMessage));
  tampered[0] ^= 0x01;

  bool still_valid = false;
  rc = pqhs_verify(suite, pk.data(), pk.size(), tampered.data(), tampered.size(), kCtx,
                    sizeof(kCtx), sig.data(), sig_len, &still_valid);
  if (rc != PQHS_OK) return Fail("verify (tampered)", rc);
  if (still_valid) return FailMsg("verify of the tampered message returned true");

  std::printf("%s: keygen, sign, verify true, tamper, verify false -- OK\n", name);
  return true;
}

}  // namespace

int main() {
  struct Check {
    uint8_t suite;
    const char *name;
  };
  const Check checks[] = {
      {1, "H1"},
      {2, "H2"},
      {3, "H3"},
      {4, "H4"},
  };

  for (const auto &check : checks) {
    if (!CheckSuite(check.suite, check.name)) {
      return 1;
    }
  }

  return 0;
}

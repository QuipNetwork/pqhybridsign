// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Signs and verifies for every suite this binding exposes (H1-H4),
// confirms H5/H6 are refused with an explanatory error rather than
// silently mishandled, and confirms a tampered message and a
// wrong-suite signature both fail verification. Also exercises
// verifyWithStoredPublicKey/storedPublicKeyLen, the one H5/H6 entry point
// this binding does expose (see lib.rs for why verification is safe where
// signing is not). Run against a `nodejs`-target build assembled by
// ../../scripts/build-npm.sh:
//
//   ../../scripts/build-npm.sh
//   node tests/node/sign_and_verify.mjs
//
// Exits nonzero on any failure, so this is safe to wire into
// continuous integration directly.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as pqhs from "../../npm/node/pqhybridsign_wasm.js";

const SUITES = ["H1", "H2", "H3", "H4"];
const MSG = new TextEncoder().encode("the message the node test signs");
const CTX = new TextEncoder().encode("node-sign-and-verify-test");

function seed(byte) {
    return new Uint8Array(32).fill(byte);
}

let failures = 0;

function check(name, fn) {
    try {
        fn();
        console.log(`ok - ${name}`);
    } catch (err) {
        failures += 1;
        console.error(`not ok - ${name}`);
        console.error(err);
    }
}

check("profileName reports a shrincs profile", () => {
    assert.match(pqhs.profileName(), /^shrincs-/);
});

for (const [i, suite] of SUITES.entries()) {
    check(`${suite}: keygen, sign, verify round-trip`, () => {
        const { secretKey, publicKey } = pqhs.keygenFromSeed(suite, seed(i + 1));
        assert.equal(secretKey.length, pqhs.secretKeyLen(suite));
        assert.equal(publicKey.length, pqhs.publicKeyLen(suite));

        const sig = pqhs.sign(suite, secretKey, MSG, CTX);
        assert.ok(sig.length <= pqhs.signatureLen(suite));
        assert.equal(pqhs.verify(suite, publicKey, MSG, CTX, sig), true);
    });

    check(`${suite}: deterministic signing is repeatable`, () => {
        const { secretKey, publicKey } = pqhs.keygenFromSeed(suite, seed(i + 1));
        const nonce = new TextEncoder().encode("fixed-nonce");
        const sigA = pqhs.signDeterministic(suite, secretKey, MSG, CTX, nonce);
        const sigB = pqhs.signDeterministic(suite, secretKey, MSG, CTX, nonce);
        assert.deepEqual(sigA, sigB);
        assert.equal(pqhs.verify(suite, publicKey, MSG, CTX, sigA), true);
    });

    check(`${suite}: a tampered message fails to verify`, () => {
        const { secretKey, publicKey } = pqhs.keygenFromSeed(suite, seed(i + 1));
        const sig = pqhs.sign(suite, secretKey, MSG, CTX);
        const tampered = new TextEncoder().encode("a different message entirely");
        assert.equal(pqhs.verify(suite, publicKey, tampered, CTX, sig), false);
    });
}

check("a signature from one suite fails to verify under another", () => {
    const { secretKey: h1sk, publicKey: h1pk } = pqhs.keygenFromSeed("H1", seed(1));
    const sig = pqhs.sign("H1", h1sk, MSG, CTX);
    const { publicKey: h3pk } = pqhs.keygenFromSeed("H3", seed(1));
    assert.equal(pqhs.verify("H1", h1pk, MSG, CTX, sig), true);
    assert.equal(pqhs.verify("H3", h3pk, MSG, CTX, sig), false);
});

for (const suite of ["H5", "H6"]) {
    check(`${suite} is refused with an explanatory error, not silently accepted`, () => {
        assert.throws(
            () => pqhs.keygenFromSeed(suite, seed(1)),
            (err) => {
                assert.ok(err instanceof Error);
                assert.match(err.message, /stateful suite/);
                assert.match(err.message, /structured-cloned/);
                return true;
            },
        );
        assert.throws(() => pqhs.publicKeyLen(suite));
        assert.throws(() => pqhs.secretKeyLen(suite));
        assert.throws(() => pqhs.signatureLen(suite));
    });
}

check("an unknown suite name is refused", () => {
    assert.throws(() => pqhs.keygenFromSeed("H7", seed(1)));
});

const MALFORMED = [
    new Uint8Array(0),
    new Uint8Array(1),
    new Uint8Array(4096),
];

for (const suite of SUITES) {
    check(`${suite}: verify returns false and does not throw for malformed lengths`, () => {
        const { secretKey, publicKey } = pqhs.keygenFromSeed(suite, seed(1));
        const sig = pqhs.sign(suite, secretKey, MSG, CTX);
        for (const bad of MALFORMED) {
            assert.equal(pqhs.verify(suite, publicKey, MSG, CTX, bad), false);
            assert.equal(pqhs.verify(suite, bad, MSG, CTX, sig), false);
        }
    });
}

// Fixture for verifyWithStoredPublicKey, generated once with the Python
// binding against Suite.H5 (see the task-4 report: no binding derives the
// stored form from a verify-form public key, so this crate cannot generate
// its own fixture without a stateful keygen it deliberately does not
// expose). `stored` is the small form a verifier installs; `bundle` is the
// signer-supplied commitment bundle for the same key; `attackerBundle` is
// the bundle of an unrelated key that signs the same message.
const fixturePath = fileURLToPath(
    new URL("./verify_with_stored_public_key.fixture.json", import.meta.url),
);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const STORED = hex(fixture.stored);
const BUNDLE = hex(fixture.bundle);
const ATTACKER_BUNDLE = hex(fixture.attackerBundle);
const STORED_MSG = hex(fixture.msg);
const STORED_CTX = hex(fixture.ctx);
const STORED_SIG = hex(fixture.sig);

check("storedPublicKeyLen(H5) matches the fixture's stored form", () => {
    assert.equal(pqhs.storedPublicKeyLen("H5"), fixture.storedLen);
    assert.equal(STORED.length, fixture.storedLen);
});

check("H1-H4 are refused by storedPublicKeyLen and verifyWithStoredPublicKey", () => {
    for (const suite of SUITES) {
        assert.throws(() => pqhs.storedPublicKeyLen(suite));
        assert.throws(() =>
            pqhs.verifyWithStoredPublicKey(suite, STORED, BUNDLE, STORED_MSG, STORED_CTX, STORED_SIG),
        );
    }
});

check("verifyWithStoredPublicKey accepts the bundle the stored key names", () => {
    assert.equal(
        pqhs.verifyWithStoredPublicKey(
            "H5",
            STORED,
            BUNDLE,
            STORED_MSG,
            STORED_CTX,
            STORED_SIG,
        ),
        true,
    );
});

check("verifyWithStoredPublicKey refuses a bundle the stored key does not name", () => {
    // The attacker's own bundle verifies the same signature's message and
    // context perfectly well as a self-consistent key; what it fails is
    // the binding to the *stored* commitment, which is what this entry
    // point exists to check.
    assert.equal(
        pqhs.verifyWithStoredPublicKey(
            "H5",
            STORED,
            ATTACKER_BUNDLE,
            STORED_MSG,
            STORED_CTX,
            STORED_SIG,
        ),
        false,
    );
});

check("verifyWithStoredPublicKey returns false and does not throw for malformed lengths", () => {
    for (const bad of MALFORMED) {
        assert.equal(
            pqhs.verifyWithStoredPublicKey("H5", bad, BUNDLE, STORED_MSG, STORED_CTX, STORED_SIG),
            false,
        );
        assert.equal(
            pqhs.verifyWithStoredPublicKey("H5", STORED, bad, STORED_MSG, STORED_CTX, STORED_SIG),
            false,
        );
    }
});

if (failures > 0) {
    console.error(`${failures} check(s) failed`);
    process.exit(1);
}
console.log("all checks passed");

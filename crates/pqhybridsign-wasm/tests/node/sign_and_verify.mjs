// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Signs and verifies for every suite this binding exposes (H1-H4),
// confirms H5/H6 are refused with an explanatory error rather than
// silently mishandled, and confirms a tampered message and a
// wrong-suite signature both fail verification. Run against a
// `nodejs`-target build assembled by ../../scripts/build-npm.sh:
//
//   ../../scripts/build-npm.sh
//   node tests/node/sign_and_verify.mjs
//
// Exits nonzero on any failure, so this is safe to wire into
// continuous integration directly.

import assert from "node:assert/strict";
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

if (failures > 0) {
    console.error(`${failures} check(s) failed`);
    process.exit(1);
}
console.log("all checks passed");

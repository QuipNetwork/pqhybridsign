// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Checks that a WebAssembly trap reaching the wrapper becomes a
// PqHybridSignPanic and that the module is reloaded before the next call.
//
// The stub tests drive createApi directly with a fake RawModule, because
// no export of the real module reaches a panic on caller-supplied input:
// every entry point is bounds-checked in pqhybridsign-abi first, which is
// the audit recorded on pqhs-dw5. Forcing a real trap would mean shipping
// an export whose only purpose is to crash. The stub covers the guard's
// contract; the last test covers the real loader's ability to run twice.

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const dist = require(join(here, "..", "dist", "index.node.cjs"));
const { createApi, PqHybridSignPanic } = dist;

// A RawModule whose profileName() throws whatever the test asks for.
function stubModule(thrown) {
  return {
    profileName() {
      if (thrown !== null) {
        throw thrown;
      }
      return "shrincs-256s";
    },
  };
}

test("a WebAssembly trap becomes a PqHybridSignPanic", async () => {
  const api = createApi(async () => stubModule(new WebAssembly.RuntimeError("unreachable")));
  await assert.rejects(
    () => api.profileName(),
    (err) => {
      assert.ok(err instanceof PqHybridSignPanic, "not a PqHybridSignPanic");
      assert.equal(err.name, "PqHybridSignPanic");
      assert.ok(err.cause instanceof WebAssembly.RuntimeError, "cause is not the trap");
      return true;
    },
  );
});

test("an ordinary error passes through unchanged", async () => {
  const original = new Error("bad length");
  const api = createApi(async () => stubModule(original));
  await assert.rejects(
    () => api.profileName(),
    (err) => {
      assert.equal(err, original, "the ordinary error was replaced");
      assert.ok(!(err instanceof PqHybridSignPanic), "an ordinary error became a panic");
      return true;
    },
  );
});

test("the module is reloaded after a trap and not before", async () => {
  let loads = 0;
  let trap = true;
  const api = createApi(async () => {
    loads += 1;
    return stubModule(trap ? new WebAssembly.RuntimeError("unreachable") : null);
  });

  await assert.rejects(() => api.profileName(), PqHybridSignPanic);
  assert.equal(loads, 1, "the first call should load once");

  trap = false;
  assert.equal(await api.profileName(), "shrincs-256s");
  assert.equal(loads, 2, "the call after a trap should reload");

  assert.equal(await api.profileName(), "shrincs-256s");
  assert.equal(loads, 2, "a call after a clean call should not reload");
});

test("the real node loader produces a working module twice", async () => {
  // Not a trap test. It checks the mechanism the recovery in the test
  // above depends on: that the shipped loader, called a second time,
  // hands back a module that still answers.
  const first = await dist.__loadForTest();
  assert.equal(typeof first.profileName(), "string");
  const second = await dist.__loadForTest();
  assert.equal(typeof second.profileName(), "string");
});

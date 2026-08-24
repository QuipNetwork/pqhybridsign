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

test("a poisoned stateful key handle rejects every later call, including export() and free()", async () => {
  // The instance behind a stateful key handle is the same instance guard
  // discards on a trap: once signStateful traps, exporting the handle must
  // not hand back whatever bytes the now-unsound instance still returns.
  let exportCalls = 0;
  let freeCalls = 0;
  const innerStub = {
    keyIdentity() {
      return new Uint8Array(32);
    },
    export() {
      exportCalls += 1;
      // Bytes a trapped instance might still hand back. The property this
      // test exists to prove is that these never reach the caller.
      return new Uint8Array(4).fill(0xee);
    },
    signStateful() {
      throw new WebAssembly.RuntimeError("unreachable");
    },
    signStateless() {
      return new Uint8Array(4);
    },
    free() {
      freeCalls += 1;
    },
  };

  const api = createApi(async () => ({
    profileName() {
      return "shrincs-256s";
    },
    StatefulKey: {
      open() {
        return innerStub;
      },
    },
  }));

  const journal = {
    commit() {},
    nextLeaf() {
      return 0;
    },
    boundKey() {
      return null;
    },
    bindKey() {},
  };

  const key = await api.openStatefulKey("H5", new Uint8Array(4));

  await assert.rejects(
    () => key.signStateful(journal, new Uint8Array(1), new Uint8Array(1)),
    PqHybridSignPanic,
  );

  await assert.rejects(() => key.export(), PqHybridSignPanic);
  assert.equal(exportCalls, 0, "export() must not call into the trapped instance");

  assert.throws(() => key.free(), PqHybridSignPanic);
  assert.equal(freeCalls, 0, "free() must not call into the trapped instance");
});

test("the real node loader produces a working module twice", async () => {
  // Not a trap test. It checks the mechanism the recovery in the test
  // above depends on: that the shipped loader, called a second time,
  // returns a DIFFERENT module object that still answers. Asserting only
  // that both answer would pass on a cached instance and prove nothing.
  const first = await dist.__loadForTest();
  assert.equal(typeof first.profileName(), "string");
  const second = await dist.__loadForTest();
  assert.equal(typeof second.profileName(), "string");
  assert.notEqual(first, second, "the loader returned the cached module");
});

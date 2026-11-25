// SPDX-License-Identifier: AGPL-3.0-or-later
import test from "node:test";
import assert from "node:assert/strict";
import { normalizeTypes } from "../../scripts/normalize-types.mjs";

const getter = "    readonly __wbg_get_result_signature: (a: number) => any;";
const setter = "    readonly __wbg_set_result_signature: (a: number, b: any) => void;";
const memory = "    readonly memory: WebAssembly.Memory;";
const declaration = (members) => `export interface InitOutput {\n${members.join("\n")}\n}\n`;

test("InitOutput getter/setter order does not cause declaration drift", () => {
  const expected = declaration([getter, setter, memory]);
  for (const members of [[memory, setter, getter], [getter, memory, setter], [setter, getter, memory]]) {
    const normalized = normalizeTypes(declaration(members));
    assert.equal(normalized, expected);
    assert.equal(normalizeTypes(normalized), normalized);
  }
});

test("normalization preserves declarations and comments outside InitOutput", () => {
  const before = "// Documentation\nexport class Example {\n    method(a: string): void;\n    method(a: any): void;\n}\n";
  const after = "// Initialization docs\nexport function init(): InitOutput;\n";
  assert.equal(
    normalizeTypes(before + declaration([setter, getter]) + after),
    before + declaration([getter, setter]) + after,
  );
});

test("signature, name, addition, and removal changes remain detectable", () => {
  const expected = normalizeTypes(declaration([getter, setter]));
  for (const members of [
    [getter.replace("=> any", "=> number"), setter],
    [getter, setter.replace("b: any", "b: number")],
    [getter.replace("signature", "publicKey"), setter],
    [getter, setter, memory],
    [getter],
  ]) {
    assert.notEqual(normalizeTypes(declaration(members)), expected);
  }
});

test("normalization does not discard duplicate declarations", () => {
  assert.equal(
    normalizeTypes(declaration([setter, getter, getter])),
    declaration([getter, getter, setter]),
  );
});

test("unexpected InitOutput syntax requires review instead of being sorted", () => {
  for (const member of ["    method(): void;", "    readonly value:\n        number;", "    // comment"]) {
    assert.throws(() => normalizeTypes(declaration([member])), /Unexpected InitOutput/);
  }
});

test("Node declarations without InitOutput remain byte-for-byte unchanged", () => {
  const source = "// Node API\nexport function verify(signature: Uint8Array): boolean;\n";
  assert.equal(normalizeTypes(source), source);
});

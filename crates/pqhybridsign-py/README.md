# pqhybridsign (Python)

Python bindings for `pqhybridsign`, a suite of six hybrid classical /
post-quantum signature schemes (ED-ML-44, ED-FN-512, SR-ML-44, SR-FN-512,
ED-SH, SR-SH), built on [`pyo3`](https://pyo3.rs) over the workspace's
type-erased `pqhybridsign-abi` crate.

ED-ML-44 through SR-FN-512 are stateless: sign and verify with `bytes` in,
`bytes` out.

ED-SH and SR-SH pair a classical scheme with SHRINCS, a stateful hash-based
scheme whose post-quantum half spends a one-time leaf per signature.
Their secret key is `StatefulSecretKey`, not `bytes`: reusing a leaf is a
total loss of the key's post-quantum security, so `StatefulSecretKey`
refuses to be copied, deep-copied or pickled.

`keygen_stateful_from_seed` and `load_stateful_secret_key` both bind a
`journal` to the `StatefulSecretKey` they return, for that key's whole
lifetime; `sign_stateful` always spends leaves through that bound journal
and takes no `journal` argument of its own. Loading the same exported key
twice must reuse the same journal object, or the same durable store behind
it, every time: two independent journals that have never seen the key both
correctly report leaf 0 as next, and nothing in this crate can tell that
apart from a legitimate restart. What binding a journal at construction
does catch, the moment the key is asked to sign, is every case where a
single journal was meant to be shared and was not kept in step: a stale
blob loaded against an already-advanced journal, an advanced blob loaded
against a journal that missed a commit, or two key objects sharing one
journal instance where the second tries to sign after the first already
has. Each of those raises `CountersDivergedError`.

`keygen_from_seed` returns the secret key as a Python `bytes` object.
A `bytes` object is immutable. This binding cannot zeroize it once the
caller holds it. The binding zeroizes every Rust copy it makes before
that copy drops. That covers only the memory this crate controls.
Callers that need the binding to zeroize the secret key on drop must use
`StatefulSecretKey` or the C ABI.

```python
import pqhybridsign as phs

sk, pk = phs.keygen_from_seed(phs.Suite.ED_ML_44, seed)
sig = phs.sign(phs.Suite.ED_ML_44, sk, b"message", b"context")
assert phs.verify(phs.Suite.ED_ML_44, pk, b"message", b"context", sig)
```

Every wheel this crate ships is built against exactly one SHRINCS profile;
compare `pqhybridsign.profile_name()` between the two sides of an
integration before trusting anything on the wire.

## Building

```bash
maturin develop
```

## Testing

```bash
maturin develop
pytest
```

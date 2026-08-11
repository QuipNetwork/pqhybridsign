# pqhybridsign (Python)

Python bindings for `pqhybridsign`, a suite of six hybrid classical /
post-quantum signature schemes (H1 through H6), built on
[`pyo3`](https://pyo3.rs) over the workspace's type-erased `pqhybridsign-abi`
crate.

H1 through H4 are stateless: sign and verify with `bytes` in, `bytes` out.

H5 and H6 pair a classical scheme with SHRINCS, a stateful hash-based
scheme whose post-quantum half spends a one-time leaf per signature.
Their secret key is `StatefulSecretKey`, not `bytes`: reusing a leaf is a
total loss of the key's post-quantum security, so `StatefulSecretKey`
refuses to be copied, deep-copied or pickled.

```python
import pqhybridsign as phs

sk, pk = phs.keygen_from_seed(phs.Suite.H1, seed)
sig = phs.sign(phs.Suite.H1, sk, b"message", b"context")
assert phs.verify(phs.Suite.H1, pk, b"message", b"context", sig)
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

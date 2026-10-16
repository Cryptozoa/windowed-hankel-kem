"""Local compatibility and arithmetic checks for the Hankel backend refactor.

These checks preserve the existing research protocol; they make no claim about
parameter strength, decryption-failure probability, or constant-time execution.
Run with ``python -m unittest -v test_hankel_refactor``.
"""

import hashlib
import unittest
from unittest import mock

import numpy as np

import hankel_kem_core as core
import hankel_kem_wrapper as wire
from hankel_kem import backends as backend_registry


# Frozen before refactoring, in review_evidence/hankel_architecture_e2080e22fe2d/results.json, and
# updated for the exact FO^{notbot} transform (v0.3): the public- and secret-key hashes are unchanged,
# the ciphertext and shared-key hashes are the new reference outputs.
BASELINE_HASHES = (
    "adfdce809d44f88c008eb4742c67865e3a42fbc2c4bc38f0978ff5c01e65b262",
    "8742d45b51a96a48770a913eed6b058631ad87df3207a675a23ae126182e2848",
    "2774ed9e3fdb1f3206c7a2e6012388e917e46c45319a42134d57a06e3d73efec",
    "8acda18b2ef04355d530a5c6e2439a3dd3e882148afa1651f0ae449d9eaf4afb",
    "8acda18b2ef04355d530a5c6e2439a3dd3e882148afa1651f0ae449d9eaf4afb",
)
BASELINE_LENGTHS = (1196, 1868, 1356, 32, 32)
EXTRA_BASELINE_HASHES = (
    ("7eb81cb922fb045616f70577f93e95743e5bd9c971337f20fd035a4f2b558b0b",
     "35d5c59181623e0178399fac128551ade688f7ba85e3d9c568d139e11c63ccde",
     "03b09b495a87f96b44bf2006d35efa0e0db4b1d00ee54a015160714249652848",
     "67bd71f6e99402793c92c9b5cd4e8cbcb4c39e85ab67c11349817b6cf5f2e2cb",
     "67bd71f6e99402793c92c9b5cd4e8cbcb4c39e85ab67c11349817b6cf5f2e2cb"),
    ("3c613c1291450035191fc7ca0b766a1c9dacfc2819284e2a2e479c05d63369fc",
     "a18ea71652254828922002758a359313c683a4c6db3bc2c7d6ec4d700e681eae",
     "e16ea8d5df0c133b52e86587d5ec6f4d677d06a8ecef3baac088a4dc5805c128",
     "97e70cfaddb2ca802213b26be4bc328fa3f830099c9aacc1929eb54d59df61ab",
     "97e70cfaddb2ca802213b26be4bc328fa3f830099c9aacc1929eb54d59df61ab"),
)


def concrete_backends():
    """Concrete usable implementations, without an auto-selection alias."""
    names = core.available_backends()
    return tuple(name for name in ("reference", "convolution", "neon") if name in names)


def independent_forward(a, x, n, m):
    """Integer index definition, independent of backend multiplication code."""
    return np.array([
        sum(int(a[i + j]) * int(x[j]) for j in range(n)) % core.Q
        for i in range(m)
    ], dtype=np.int64)


def independent_project(x, y, n, w):
    return np.array([
        sum(int(x[j]) * int(y[j + offset]) for j in range(n)) % core.Q
        for offset in range(w)
    ], dtype=np.int64)


def handshake(backend, seed=bytes(range(64)), entropy=bytes(range(32))):
    pk, sk = wire.hankel_kem_keygen(seed, backend=backend)
    ct, sender = wire.hankel_kem_encaps(pk, entropy, backend=backend)
    receiver = wire.hankel_kem_decaps(ct, sk, backend=backend)
    return pk, sk, ct, sender, receiver


class TestHankelRefactor(unittest.TestCase):
    def test_frozen_wire_fixture_and_keyword_backends(self):
        self.assertIn("reference", core.available_backends())
        self.assertIn("convolution", core.available_backends())
        for backend in concrete_backends() + ("auto",):
            with self.subTest(backend=backend):
                outputs = handshake(backend)
                self.assertEqual(tuple(map(len, outputs)), BASELINE_LENGTHS)
                self.assertEqual(tuple(hashlib.sha256(x).hexdigest() for x in outputs), BASELINE_HASHES)
                self.assertEqual(outputs[3], outputs[4])
                pk, _, ct, _, _ = outputs
                self.assertEqual(wire.serialize_public_key(wire.deserialize_public_key(pk)), pk)
                u, v, n, w, q = wire.deserialize_ciphertext(ct)
                self.assertEqual(wire.serialize_ciphertext(u, v, n, w, q), ct)

    def test_several_deterministic_wire_fixtures_agree(self):
        fixtures = ((b"A" * 64, b"B" * 32), (bytes(reversed(range(64))), b"\x00" * 32))
        # These extra hashes were first obtained with the pristine old core/wrapper snapshot above, with its
        # _C_LIB disabled in an isolated process; the ciphertext and key entries are now those of v0.3.
        for (seed, entropy), frozen_hashes in zip(fixtures, EXTRA_BASELINE_HASHES):
            expected = handshake("reference", seed, entropy)
            self.assertEqual(tuple(hashlib.sha256(x).hexdigest() for x in expected), frozen_hashes)
            self.assertEqual(expected[3], expected[4])
            for backend in concrete_backends():
                with self.subTest(seed_hash=hashlib.sha256(seed).hexdigest(), backend=backend):
                    self.assertEqual(handshake(backend, seed, entropy), expected)

    def test_backend_context_nesting_and_exception_restoration(self):
        original = core.get_backend_name()
        with core.use_backend("reference"):
            self.assertEqual(core.get_backend_name(), "reference")
            contextual = wire.hankel_kem_keygen(bytes(range(64)))
            self.assertEqual(contextual, wire.hankel_kem_keygen(bytes(range(64)), backend="reference"))
            with core.use_backend("convolution"):
                self.assertEqual(core.get_backend_name(), "convolution")
                self.assertEqual(wire.hankel_kem_keygen(bytes(range(64))), contextual)
            self.assertEqual(core.get_backend_name(), "reference")
            try:
                with core.use_backend("convolution"):
                    raise LookupError("test context restoration")
            except LookupError:
                pass
            self.assertEqual(core.get_backend_name(), "reference")
        self.assertEqual(core.get_backend_name(), original)

    def test_primitive_arithmetic_including_non_multiple_of_eight(self):
        rng = np.random.default_rng(2026100307)
        native = backend_registry.resolve_backend("neon") if "neon" in concrete_backends() else None
        for n, m, w in ((1, 5, 3), (7, 11, 4), (8, 13, 5), (640, 768, 128)):
            a = rng.integers(0, core.Q, n + m - 1, dtype=np.int64)
            x = rng.integers(-2, 3, n, dtype=np.int64)
            y = rng.integers(0, core.Q, n + w, dtype=np.int64)
            error = rng.integers(-2, 3, m, dtype=np.int64)
            expected_forward = independent_forward(a, x, n, m)
            expected_project = independent_project(x, y, n, w)
            backends = ("reference", "convolution")
            if native is not None and (n % 8 == 0 or native.supports_tails):
                backends += ("neon",)
            for backend in backends:
                with self.subTest(n=n, m=m, w=w, backend=backend):
                    got = core.hankel_forward_multiply(a, x, n, m, backend=backend)
                    np.testing.assert_array_equal(got, expected_forward)
                    fused = core.hankel_forward_multiply(a, x, n, m, backend=backend, error=error)
                    np.testing.assert_array_equal(fused, (expected_forward + error) % core.Q)
                    projected = core.hankel_window_project(x, y, n, w, backend=backend)
                    np.testing.assert_array_equal(projected, expected_project)

    def test_pairing_identity_and_ciphertext_e2_are_preserved(self):
        # Distinct secrets and asymmetric dimensions catch reversal/window errors.
        rng = np.random.default_rng(2026100308)
        n, w = 7, 5
        a = rng.integers(0, core.Q, 2 * n + w - 1, dtype=np.int64)
        s = rng.integers(-2, 3, n, dtype=np.int64)
        r = rng.integers(-2, 3, n, dtype=np.int64)
        expected = np.array([
            sum(int(r[i]) * int(s[j]) * int(a[i + j + offset])
                for i in range(n) for j in range(n)) % core.Q
            for offset in range(w)
        ], dtype=np.int64)
        for backend in ("reference", "convolution"):
            b = core.hankel_forward_multiply(a, s, n, n + w, backend=backend)
            u = core.hankel_forward_multiply(a, r, n, n + w, backend=backend)
            np.testing.assert_array_equal(core.hankel_window_project(r, b, n, w, backend=backend), expected)
            np.testing.assert_array_equal(core.hankel_window_project(s, u, n, w, backend=backend), expected)

        seed_a, b, _ = core.hankel_kem_cpa_keygen(bytes(range(64)), backend="reference")
        msg, coins = bytes(range(32)), b"e2-preservation-fixture"
        raw = hashlib.shake_256(coins + b"_hankel_encaps_coins").digest(core.N + core.M_LEN + core.W)
        # Independent CBD2 decoding of the published four-bit sampling rule.
        noise = np.array([((v & 1) + ((v >> 1) & 1) - ((v >> 2) & 1) - ((v >> 3) & 1))
                          for v in raw], dtype=np.int64)
        r, e2 = noise[:core.N], noise[core.N + core.M_LEN:]
        self.assertTrue(np.any(e2 != 0), "fixture must distinguish dropping e2")
        points = np.array([1024 * ((byte >> shift) & 3)
                           for byte in msg for shift in (0, 2, 4, 6)], dtype=np.int64)
        expected_v = (independent_project(r, b, core.N, core.W) + points + e2) % core.Q
        for backend in concrete_backends():
            _, v = core.hankel_kem_cpa_encaps(seed_a, b, msg, coins, backend=backend)
            np.testing.assert_array_equal(v, expected_v)

    def test_implicit_rejection_binds_exact_received_bytes(self):
        pk, sk, ct, sender, _ = handshake("reference")
        del pk
        changed = bytearray(ct)
        changed[30] ^= 1
        reserved = bytearray(ct)
        reserved[10] = 1
        cases = (bytes(changed), bytes(reserved), ct[:19], ct + b"\x00", b"")
        reject_seed = sk[core.N:core.N + 32]
        for malformed in cases:
            expected = hashlib.shake_256(reject_seed + malformed + b"_hankel_fo_H").digest(32)  # H(z, ct)
            self.assertNotEqual(expected, sender)
            for backend in concrete_backends():
                with self.subTest(length=len(malformed), backend=backend):
                    self.assertEqual(wire.hankel_kem_decaps(malformed, sk, backend=backend), expected)

    def test_guarded_bad_inputs_and_explicit_native_shape(self):
        a = np.zeros(core.TOTAL_A_LEN, dtype=np.int64)
        x = np.zeros(core.N, dtype=np.int64)
        y = np.zeros(core.M_LEN, dtype=np.int64)
        for backend in concrete_backends():
            calls = (
                lambda: core.hankel_forward_multiply(a[:-1], x, backend=backend),
                lambda: core.hankel_forward_multiply(a, x[:-1], backend=backend),
                lambda: core.hankel_forward_multiply(a.reshape(1, -1), x, backend=backend),
                lambda: core.hankel_forward_multiply(a.astype(float), x, backend=backend),
                lambda: core.hankel_forward_multiply(a, x, n=0, backend=backend),
                lambda: core.hankel_forward_multiply(a, x, error=np.zeros(core.M_LEN - 1, dtype=np.int64), backend=backend),
                lambda: core.hankel_window_project(x, y[:5], backend=backend),
                lambda: core.decode_message_4pam_256(np.zeros(core.W - 1, dtype=np.int64), backend=backend),
            )
            for i, call in enumerate(calls):
                with self.subTest(backend=backend, bad_input=i):
                    with self.assertRaises((ValueError, TypeError)):
                        call()
        # A loaded native implementation must either support the tail correctly
        # or reject this geometry explicitly; unavailable native must reject.
        if "neon" in concrete_backends():
            try:
                got = core.hankel_forward_multiply(np.arange(17, dtype=np.int64), np.ones(7, dtype=np.int64),
                                                   n=7, m=11, backend="neon")
            except (ValueError, RuntimeError):
                pass
            else:
                np.testing.assert_array_equal(got, independent_forward(np.arange(17), np.ones(7), 7, 11))
        else:
            with self.assertRaises((ValueError, RuntimeError)):
                core.hankel_forward_multiply(a, x, backend="neon")
        with self.assertRaises((ValueError, RuntimeError)):
            core.hankel_forward_multiply(a, x, backend="missing-backend")

    def test_explicit_backend_failures_are_not_hidden(self):
        a = np.zeros(core.TOTAL_A_LEN, dtype=np.int64)
        x = np.zeros(core.N, dtype=np.int64)
        reference = backend_registry.resolve_backend("reference")
        with mock.patch.object(reference, "forward", side_effect=RuntimeError("synthetic reference failure")):
            with self.assertRaisesRegex(RuntimeError, "synthetic reference failure"):
                core.hankel_forward_multiply(a, x, backend="reference")
        if "neon" in concrete_backends():
            self.assertTrue(core.is_native_loaded())
            native = backend_registry.resolve_backend("neon")
            with mock.patch.object(native, "forward", side_effect=RuntimeError("synthetic native failure")):
                with mock.patch.object(reference, "forward", side_effect=AssertionError("fallback must not run")):
                    with self.assertRaisesRegex(RuntimeError, "synthetic native failure"):
                        core.hankel_forward_multiply(a, x, backend="neon")
        software = {name: backend_registry.resolve_backend(name) for name in ("reference", "convolution")}
        with mock.patch.dict(backend_registry._BACKENDS, software, clear=True):
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                core.hankel_forward_multiply(a, x, backend="neon")
            np.testing.assert_array_equal(core.hankel_forward_multiply(a, x, backend="auto"), np.zeros(core.M_LEN))

    def test_invalid_buffers_do_not_reach_native_symbols(self):
        if "neon" not in concrete_backends():
            self.skipTest("native library absent; no native-execution claim")
        self.assertTrue(core.is_native_loaded())
        native = backend_registry.resolve_backend("neon")
        a = np.zeros(core.TOTAL_A_LEN, dtype=np.int64)
        x = np.zeros(core.N, dtype=np.int64)
        invalid_arrays = (
            a[:-1], a.reshape(1, -1), a.astype(float),
            np.full(core.TOTAL_A_LEN, core.Q, dtype=np.int64),
            np.full(core.TOTAL_A_LEN, -1, dtype=np.int64),
            np.ma.array(a, mask=False), a.astype("timedelta64[s]"),
        )
        with mock.patch.object(native.library, "hankel_neon_forward_mul", side_effect=AssertionError("native entry reached")) as entry:
            for bad in invalid_arrays:
                with self.subTest(dtype=str(bad.dtype), shape=bad.shape):
                    with self.assertRaises((ValueError, TypeError)):
                        core.hankel_forward_multiply(bad, x, backend="neon")
            entry.assert_not_called()

    def test_fused_error_is_included_in_native_accumulator_guard(self):
        # The dot alone is INT32_MAX-127. Adding 128 crosses the signed-int32
        # boundary; checking the dot bound without the error admitted this input.
        n, m = 32, 1
        a = np.full(n + m - 1, core.Q_MASK, dtype=np.int64)
        x = np.full(n, 16388, dtype=np.int64)
        error = np.array([128], dtype=np.int64)
        exact_sum = sum(int(a[j]) * int(x[j]) for j in range(n)) + int(error[0])
        self.assertEqual(exact_sum, 2**31)
        expected = np.array([exact_sum % core.Q], dtype=np.int64)
        for backend in ("reference", "convolution"):
            with self.subTest(backend=backend):
                np.testing.assert_array_equal(
                    core.hankel_forward_multiply(a, x, n, m, backend=backend, error=error), expected)
        if "neon" not in concrete_backends():
            self.skipTest("native library absent; software exact arithmetic checked")
        self.assertTrue(core.is_native_loaded())
        native = backend_registry.resolve_backend("neon")
        with mock.patch.object(native.library, "hankel_neon_forward_mul", side_effect=AssertionError("native entry reached")) as entry:
            with self.assertRaises(ValueError):
                core.hankel_forward_multiply(a, x, n, m, backend="neon", error=error)
            entry.assert_not_called()


if __name__ == "__main__":
    unittest.main()

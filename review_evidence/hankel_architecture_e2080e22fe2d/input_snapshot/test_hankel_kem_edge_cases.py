#!/usr/bin/env python3
import os
import unittest
from unittest.mock import patch
import numpy as np

from hankel_kem_core import (
    N, W, Q_MASK,
    encode_message_4pam_256,
    decode_message_4pam_256,
    hankel_kem_cpa_keygen
)
from hankel_kem_wrapper import (
    hankel_kem_keygen,
    hankel_kem_encaps,
    hankel_kem_decaps
)

class TestHankelKEMEdgeCases(unittest.TestCase):

    def test_asymmetric_voronoi_boundary(self):
        """
        Verifies the exact asymmetric boundary of the branchless Voronoi decoder.
        Valid noise range is [-512, 511].
        """
        test_m = os.urandom(32)
        enc = encode_message_4pam_256(test_m)

        # +511 should PASS
        noisy_pos_511 = (enc + 511) & Q_MASK
        self.assertEqual(decode_message_4pam_256(noisy_pos_511), test_m, "Noise +511 failed but should pass")

        # -511 should PASS
        noisy_neg_511 = (enc - 511) & Q_MASK
        self.assertEqual(decode_message_4pam_256(noisy_neg_511), test_m, "Noise -511 failed but should pass")

        # -512 should PASS (asymmetric advantage on the negative side due to (x+512) logic)
        noisy_neg_512 = (enc - 512) & Q_MASK
        self.assertEqual(decode_message_4pam_256(noisy_neg_512), test_m, "Noise -512 failed but should pass")

        # +512 should FAIL
        noisy_pos_512 = (enc + 512) & Q_MASK
        self.assertNotEqual(decode_message_4pam_256(noisy_pos_512), test_m, "Noise +512 succeeded but should fail")


    def test_ciphertext_underflow_rejection(self):
        """
        Verifies that a heavily truncated ciphertext buffer does not crash the Python
        interpreter (via index out-of-bounds or unpack exceptions) and correctly routes
        to the constant-time implicit rejection key.
        """
        pk_bytes, sk_bytes = hankel_kem_keygen()
        ct_bytes, honest_ss = hankel_kem_encaps(pk_bytes)

        # Truncate the ciphertext to just 50 bytes (well below the expected 1356 bytes)
        truncated_ct = ct_bytes[:50]

        # This should NOT throw an exception, but return a valid 32-byte rejection key
        try:
            reject_ss = hankel_kem_decaps(truncated_ct, sk_bytes)
        except Exception as e:
            self.fail(f"Decapsulation threw an exception on underflow: {e}")

        self.assertEqual(len(reject_ss), 32)
        self.assertNotEqual(reject_ss, honest_ss, "Underflow CT yielded the honest shared secret!")


    @patch('hankel_kem_core.sample_cbd2_from_bytes')
    def test_zero_vector_mitigation(self, mock_cbd):
        """
        Simulates a catastrophic OS RNG failure where CBD sampling yields pure zero vectors.
        Verifies that the constant-time mitigation flips s[0] to 1 to prevent key collapse.
        """
        # Mock CBD to always return an array of zeros
        def mock_cbd_side_effect(buf, count):
            return np.zeros(count, dtype=np.int64)
        mock_cbd.side_effect = mock_cbd_side_effect

        seed = os.urandom(64)
        _, _, s = hankel_kem_cpa_keygen(seed=seed, n=N, w_len=W)

        # The mitigation should have detected all zeros and forced s[0] to 1
        self.assertEqual(s[0], 1, "Zero-vector mitigation failed to set s[0] to 1")
        
        # The rest of the vector should remain 0
        self.assertTrue(np.all(s[1:] == 0), "Mitigation altered coordinates other than s[0]")


if __name__ == '__main__':
    unittest.main(verbosity=2)

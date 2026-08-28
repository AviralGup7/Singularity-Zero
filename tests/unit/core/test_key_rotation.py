import unittest

from src.core.frontier.receipt_crypto import (
    GLOBAL_KEY_RING,
    receipt_bind_payload,
    sign_receipt,
    verify_receipt_signature,
)


class TestAuthorityKeyRotation(unittest.TestCase):
    def setUp(self) -> None:
        # Save baseline key state
        self.initial_key_id = GLOBAL_KEY_RING.active_key_id
        self.initial_gen = GLOBAL_KEY_RING.active_generation

    def tearDown(self) -> None:
        # Restore key ring state
        GLOBAL_KEY_RING._active_key_id = self.initial_key_id
        GLOBAL_KEY_RING._active_generation = self.initial_gen

    def test_key_rotation_and_overlap_verification(self) -> None:
        """Receipt signed under Generation 1 must verify both before and after rotation to Generation 2."""
        # 1. Sign receipt under generation 1
        payload_g1 = receipt_bind_payload(
            command_id="cmd_rot_1",
            partition_id="P-0000",
            raft_term=1,
            raft_index=10,
            entry_hash="hash_10",
            previous_state_hash="prev_0",
            state_hash_at_commit="post_10",
            signer_key_id=GLOBAL_KEY_RING.active_key_id,
            key_generation=GLOBAL_KEY_RING.active_generation,
        )
        sig_g1 = sign_receipt(payload_g1)
        self.assertTrue(verify_receipt_signature(payload_g1, sig_g1))

        # 2. Perform key rotation ceremony (e.g. Raft-committed RotateAuthorityKey)
        new_key_id = "authority-hmac-v2"
        new_secret = b"new_super_secret_master_key_material_v2"
        record = GLOBAL_KEY_RING.rotate_key(new_key_id, new_secret)
        self.assertEqual(record.generation, self.initial_gen + 1)
        self.assertEqual(GLOBAL_KEY_RING.active_key_id, new_key_id)

        # 3. Sign receipt under generation 2
        payload_g2 = receipt_bind_payload(
            command_id="cmd_rot_2",
            partition_id="P-0000",
            raft_term=1,
            raft_index=11,
            entry_hash="hash_11",
            previous_state_hash="post_10",
            state_hash_at_commit="post_11",
            signer_key_id=new_key_id,
            key_generation=record.generation,
        )
        sig_g2 = sign_receipt(payload_g2)
        self.assertTrue(verify_receipt_signature(payload_g2, sig_g2))

        # 4. Two-key overlap verification: Historical receipt signed under G1 still verifies!
        self.assertTrue(verify_receipt_signature(payload_g1, sig_g1))

        # 5. Forged signature must fail verification
        tampered_sig = sig_g2[:-2] + "ff"
        self.assertFalse(verify_receipt_signature(payload_g2, tampered_sig))


if __name__ == "__main__":
    unittest.main()

import unittest

from cryptography.exceptions import InvalidTag

import crypto_utils


class TestSecurity(unittest.TestCase):

    def test_bitflip_rejected(self):
        key = b"A" * 16
        iv_base = b"B" * 4

        sender_id = b"C" * 16
        recipient_id = b"D" * 16

        plaintext = b"Mensagem confidencial"

        nonce, ciphertext = crypto_utils.encrypt_message(
            key,
            iv_base,
            0,
            sender_id,
            recipient_id,
            plaintext,
        )

        # Adultera um bit do texto cifrado.
        altered = bytearray(ciphertext)
        altered[0] ^= 1

        # A autenticação deve rejeitar a mensagem adulterada.
        with self.assertRaises(InvalidTag):
            crypto_utils.decrypt_message(
                key,
                iv_base,
                0,
                sender_id,
                recipient_id,
                nonce,
                bytes(altered),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

import unittest
import uuid

from cryptography.exceptions import InvalidTag

import crypto_utils
import protocol


class RecipientOnlyTest(unittest.TestCase):

    def test_only_intended_recipient_can_decrypt(self):
        # Três clientes independentes: A, B e C.
        a_id = uuid.uuid4().bytes
        b_id = uuid.uuid4().bytes
        c_id = uuid.uuid4().bytes

        # Cada cliente possui seu próprio salt de sessão.
        salt_a = crypto_utils.os.urandom(16)
        salt_b = crypto_utils.os.urandom(16)
        salt_c = crypto_utils.os.urandom(16)

        # A e B derivam o segredo compartilhado.
        private_a, public_a = crypto_utils.generate_x25519_keypair()
        private_b, public_b = crypto_utils.generate_x25519_keypair()
        private_c, public_c = crypto_utils.generate_x25519_keypair()

        secret_ab = crypto_utils.derive_shared_secret(
            private_a, public_b
        )

        pair_salt_ab = protocol.pair_salt(
            a_id, b_id, salt_a, salt_b
        )

        key_a2b, key_b2a = crypto_utils.derive_directional_keys(
            secret_ab, pair_salt_ab
        )

        iv_a2b, iv_b2a = crypto_utils.derive_directional_iv_bases(
            secret_ab, pair_salt_ab
        )

        # A escolhe a chave e a IV corretas para enviar a B.
        a_is_lower = protocol.i_am_a(a_id, b_id)

        if a_is_lower:
            send_key = key_a2b
            send_iv = iv_a2b
        else:
            send_key = key_b2a
            send_iv = iv_b2a

        mensagem = b"Mensagem secreta: somente B deve conseguir ler."

        nonce, ciphertext = crypto_utils.encrypt_message(
            send_key,
            send_iv,
            0,
            a_id,
            b_id,
            mensagem,
        )

        # B deriva independentemente o mesmo segredo de A-B.
        secret_ba = crypto_utils.derive_shared_secret(
            private_b, public_a
        )

        self.assertEqual(secret_ab, secret_ba)

        keys_ba = crypto_utils.derive_directional_keys(
            secret_ba, pair_salt_ab
        )
        ivs_ba = crypto_utils.derive_directional_iv_bases(
            secret_ba, pair_salt_ab
        )

        if protocol.i_am_a(b_id, a_id):
            receive_key_b = keys_ba[1]
            receive_iv_b = ivs_ba[1]
        else:
            receive_key_b = keys_ba[0]
            receive_iv_b = ivs_ba[0]

        # O destinatário B consegue decifrar.
        texto_b = crypto_utils.decrypt_message(
            receive_key_b,
            receive_iv_b,
            0,
            a_id,
            b_id,
            nonce,
            ciphertext,
        )

        self.assertEqual(texto_b, mensagem)

        # C deriva suas próprias chaves com A.
        secret_ca = crypto_utils.derive_shared_secret(
            private_c, public_a
        )

        pair_salt_ca = protocol.pair_salt(
            c_id, a_id, salt_c, salt_a
        )

        keys_ca = crypto_utils.derive_directional_keys(
            secret_ca, pair_salt_ca
        )

        # Identifica a chave de recebimento de C para mensagens de A.
        if protocol.i_am_a(c_id, a_id):
            receive_key_c = keys_ca[1]
        else:
            receive_key_c = keys_ca[0]

        # C conhece o nonce e os dados públicos da mensagem,
        # mas não possui a chave E2E correta.
        with self.assertRaises(InvalidTag):
            crypto_utils.decrypt_message(
                receive_key_c,
                nonce[:4],
                0,
                a_id,
                b_id,
                nonce,
                ciphertext,
            )


if __name__ == "__main__":
    unittest.main()

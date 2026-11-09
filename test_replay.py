
import asyncio
import unittest

import crypto_utils
import protocol
from client import SecureClient, PeerState


class TestReplayProtection(unittest.TestCase):

    def test_replay_message_rejected(self):
        # Identificadores fictícios para o teste.
        sender_id = b"S" * 16
        recipient_id = b"R" * 16

        # Chave e IV compartilhadas neste teste.
        key = b"K" * 16
        iv_base = b"I" * 4

        # Cria um cliente receptor.
        receiver = SecureClient(
            "127.0.0.1",
            8765,
            "00",
            "Receptor"
        )
        receiver.client_id = recipient_id

        # Simula o peer remetente já registrado.
        receiver.peers[sender_id] = PeerState(
            client_id=sender_id,
            public_key=b"P" * 32,
            salt_srv=b"S" * 16,
            key_send=key,
            key_recv=key,
            iv_base_send=iv_base,
            iv_base_recv=iv_base,
            seq_send=0,
            seq_recv=-1,
        )

        # Criptografa uma mensagem legítima.
        nonce, ciphertext = crypto_utils.encrypt_message(
            key,
            iv_base,
            0,
            sender_id,
            recipient_id,
            b"Mensagem original"
        )

        # Monta o pacote que será recebido.
        packet = protocol.pack_data(
            nonce,
            sender_id,
            recipient_id,
            0,
            ciphertext
        )

        # Primeira entrega: deve ser aceita.
        asyncio.run(receiver._handle_data(packet))

        # Segunda entrega do mesmo pacote: deve ser rejeitada.
        with self.assertRaisesRegex(ValueError, "Replay"):
            asyncio.run(receiver._handle_data(packet))


if __name__ == "__main__":
    unittest.main(verbosity=2)

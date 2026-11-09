
import asyncio
import struct
import unittest

import protocol


HOST = "127.0.0.1"
PORT = 8765


class TestFramingInvalid(unittest.IsolatedAsyncioTestCase):

    async def test_zero_length_frame_disconnects(self):
        await self.check_invalid_frame(0)

    async def test_oversized_frame_disconnects(self):
        await self.check_invalid_frame(protocol.MAX_FRAME + 1)

    async def check_invalid_frame(self, frame_size):
        reader, writer = await asyncio.open_connection(HOST, PORT)

        try:
            # Envia somente o cabeçalho com tamanho inválido.
            writer.write(struct.pack(">I", frame_size))
            await writer.drain()

            # O servidor deve encerrar a conexão.
            received = await asyncio.wait_for(
                reader.read(1),
                timeout=3
            )

            self.assertEqual(
                received,
                b"",
                "O servidor deveria ter encerrado a conexão."
            )

        finally:
            writer.close()
            await writer.wait_closed()


if __name__ == "__main__":
    unittest.main(verbosity=2)

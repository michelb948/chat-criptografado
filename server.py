"""Servidor relay da Mensageria Segura - compatível com Python 3.9.

O servidor autentica sua identidade no handshake e encaminha DATA sem
descriptografar. Ele não deriva nem armazena chaves simétricas E2E.
"""

import argparse
import asyncio
import logging
import signal
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import protocol


HOST_DEFAULT = "127.0.0.1"
PORT_DEFAULT = 8765


@dataclass
class ClientSession:
    client_id: bytes
    pk_client: bytes
    salt_srv: bytes
    writer: asyncio.StreamWriter
    admin_seq: int = 0


class SecureRelayServer:
    def __init__(self, cert_path: str, key_path: str):
        self.cert_path = Path(cert_path)
        self.key_path = Path(key_path)
        self.sessions: Dict[bytes, ClientSession] = {}
        self.lock = asyncio.Lock()

        if not self.cert_path.is_file():
            raise FileNotFoundError("Certificado não encontrado: {}".format(self.cert_path))
        if not self.key_path.is_file():
            raise FileNotFoundError("Chave privada não encontrada: {}".format(self.key_path))

        cert_pem = self.cert_path.read_bytes()
        key_pem = self.key_path.read_bytes()

        self.certificate = x509.load_pem_x509_certificate(cert_pem)
        self.private_key = serialization.load_pem_private_key(
            key_pem,
            password=None,
        )

        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise TypeError("A chave privada do servidor precisa ser RSA.")
        if self.private_key.key_size < 2048:
            raise ValueError("A chave RSA do servidor precisa ter pelo menos 2048 bits.")

        cert_public_der = self.certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_public_der = protocol.public_key_der(self.private_key.public_key())

        if cert_public_der != private_public_der:
            raise ValueError("O certificado e a chave privada não correspondem.")

        # O protocolo transporta o certificado em DER.
        self.certificate_der = self.certificate.public_bytes(
            serialization.Encoding.DER
        )
        self.public_key_der = cert_public_der

    async def send_admin(
        self,
        session: ClientSession,
        frame_type: protocol.FrameType,
        payload: bytes,
    ) -> None:
        """Envia aviso administrativo assinado especificamente para o cliente."""
        seq = session.admin_seq
        digest = protocol.admin_hash(
            frame_type,
            session.salt_srv,
            seq,
            payload,
        )
        signature = protocol.sign_digest(self.private_key, digest)
        body = protocol.pack_admin(frame_type, payload, seq, signature)
        await protocol.send_frame(session.writer, body)
        session.admin_seq += 1

    async def send_error(
        self,
        session: ClientSession,
        error_code: protocol.ErrorCode,
    ) -> None:
        try:
            payload = protocol.build_error_payload(error_code)
            await self.send_admin(session, protocol.FrameType.ERROR, payload)
        except Exception:
            pass

    async def perform_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> ClientSession:
        frame = await protocol.recv_frame(reader)
        if frame.type != protocol.FrameType.CLIENT_HELLO:
            raise protocol.ProtocolError(
                "Primeiro frame precisa ser CLIENT_HELLO",
                protocol.ErrorCode.UNKNOWN_TYPE,
            )

        hello = protocol.parse_client_hello(frame.body)

        try:
            parsed_uuid = uuid.UUID(bytes=hello.client_id)
        except ValueError as exc:
            raise protocol.ProtocolError(
                "client_id não é um UUID válido",
                protocol.ErrorCode.FRAMING_INVALID,
            ) from exc

        if parsed_uuid.version != 4:
            raise protocol.ProtocolError(
                "client_id precisa ser UUID versão 4",
                protocol.ErrorCode.FRAMING_INVALID,
            )

        salt_srv = __import__("os").urandom(protocol.SALT_LEN)
        digest = protocol.handshake_hash(
            self.public_key_der,
            hello.pk_client,
            hello.client_id,
            salt_srv,
        )
        signature = protocol.sign_digest(self.private_key, digest)

        server_hello = protocol.pack_server_hello(
            salt_srv=salt_srv,
            pk_server=self.public_key_der,
            server_cert=self.certificate_der,
            signature=signature,
        )
        await protocol.send_frame(writer, server_hello)

        return ClientSession(
            client_id=hello.client_id,
            pk_client=hello.pk_client,
            salt_srv=salt_srv,
            writer=writer,
        )

    async def register(self, session: ClientSession) -> None:
        """Registra o cliente e troca informações públicas com os peers online."""
        old_session: Optional[ClientSession] = None

        async with self.lock:
            old_session = self.sessions.pop(session.client_id, None)
            existing_sessions = list(self.sessions.values())
            self.sessions[session.client_id] = session

        # Se o mesmo UUID reconectar, encerra a conexão antiga e informa a saída.
        if old_session is not None:
            old_session.writer.close()
            try:
                await old_session.writer.wait_closed()
            except Exception:
                pass
            for peer in existing_sessions:
                try:
                    await self.send_admin(
                        peer,
                        protocol.FrameType.PEER_LEFT,
                        protocol.build_peer_left_payload(session.client_id),
                    )
                except Exception:
                    pass

        # O cliente novo recebe a lista dos peers que já estavam conectados.
        for peer in existing_sessions:
            try:
                payload = protocol.build_peer_joined_payload(
                    peer.client_id,
                    peer.pk_client,
                    peer.salt_srv,
                )
                await self.send_admin(
                    session,
                    protocol.FrameType.PEER_JOINED,
                    payload,
                )
            except Exception:
                logging.warning(
                    "Falha ao notificar peer existente ao cliente %s",
                    session.client_id.hex()[:8],
                )

        # Os clientes existentes recebem a chave pública e o salt do novo peer.
        new_peer_payload = protocol.build_peer_joined_payload(
            session.client_id,
            session.pk_client,
            session.salt_srv,
        )
        for peer in existing_sessions:
            try:
                await self.send_admin(
                    peer,
                    protocol.FrameType.PEER_JOINED,
                    new_peer_payload,
                )
            except Exception:
                logging.warning(
                    "Falha ao notificar cliente %s sobre novo peer",
                    peer.client_id.hex()[:8],
                )

        logging.info(
            "Cliente conectado: %s (clientes online: %d)",
            session.client_id.hex()[:8],
            len(self.sessions),
        )

    async def unregister(self, session: ClientSession) -> None:
        """Remove somente a sessão correspondente a esta conexão."""
        async with self.lock:
            current = self.sessions.get(session.client_id)
            if current is not session:
                return
            self.sessions.pop(session.client_id, None)
            peers = list(self.sessions.values())

        for peer in peers:
            try:
                await self.send_admin(
                    peer,
                    protocol.FrameType.PEER_LEFT,
                    protocol.build_peer_left_payload(session.client_id),
                )
            except Exception:
                pass

        logging.info(
            "Cliente desconectado: %s (clientes online: %d)",
            session.client_id.hex()[:8],
            len(self.sessions),
        )

    async def relay_data(self, session: ClientSession, body: bytes) -> None:
        """Valida o roteamento e encaminha o frame DATA intacto."""
        sender_id, recipient_id = protocol.peek_ids(body)

        if sender_id != session.client_id:
            raise protocol.ProtocolError(
                "sender_id não corresponde à sessão autenticada",
                protocol.ErrorCode.FRAMING_INVALID,
            )
        if recipient_id == session.client_id:
            raise protocol.ProtocolError(
                "Não é permitido enviar DATA para o próprio cliente",
                protocol.ErrorCode.FRAMING_INVALID,
            )

        async with self.lock:
            recipient = self.sessions.get(recipient_id)

        if recipient is None:
            await self.send_error(session, protocol.ErrorCode.PEER_OFFLINE)
            return

        # O corpo é encaminhado sem parsear ciphertext, nonce ou chaves E2E.
        await protocol.send_frame(recipient.writer, body)

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peername = writer.get_extra_info("peername")
        session: Optional[ClientSession] = None

        try:
            session = await self.perform_handshake(reader, writer)
            await self.register(session)

            while True:
                frame = await protocol.recv_frame(reader)

                if frame.type == protocol.FrameType.DATA:
                    await self.relay_data(session, frame.body)
                else:
                    raise protocol.ProtocolError(
                        "Cliente enviou tipo de frame não permitido",
                        protocol.ErrorCode.UNKNOWN_TYPE,
                    )

        except protocol.ConnectionClosed:
            pass
        except protocol.ProtocolError as exc:
            logging.warning("Conexão rejeitada (%s): %s", peername, exc)
            if session is not None:
                await self.send_error(
                    session,
                    exc.code if isinstance(exc.code, protocol.ErrorCode)
                    else protocol.ErrorCode.FRAMING_INVALID,
                )
        except (ConnectionError, asyncio.CancelledError):
            pass
        except Exception:
            logging.exception("Erro inesperado ao atender conexão %s", peername)
        finally:
            if session is not None:
                await self.unregister(session)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self, host: str, port: int) -> None:
        server = await asyncio.start_server(
            self.handle_client,
            host,
            port,
            limit=protocol.MAX_FRAME + 4,
        )
        addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
        logging.info("Servidor relay ouvindo em %s", addresses)
        async with server:
            await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Servidor relay da Mensageria Segura"
    )
    parser.add_argument("--host", default=HOST_DEFAULT)
    parser.add_argument("--port", type=int, default=PORT_DEFAULT)
    parser.add_argument("--cert", default="certs/server.crt")
    parser.add_argument("--key", default="certs/server.key")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    relay = SecureRelayServer(args.cert, args.key)
    try:
        asyncio.run(relay.start(args.host, args.port))
    except KeyboardInterrupt:
        logging.info("Servidor encerrado pelo operador.")


if __name__ == "__main__":
    main()

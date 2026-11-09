"""
protocol.py - Definições de constantes, estruturas e utilitários do protocolo.
Versão direta conforme PROTOCOLO_DIRETO.md.
"""

import asyncio
from enum import IntEnum
import hashlib
import struct
from typing import NamedTuple, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ==========================================
# CONSTANTES DE TAMANHO (em bytes)
# ==========================================
MAX_FRAME = 8192

ID_LEN = 16         # client_id, sender_id, recipient_id (UUID v4 binário)
PK_LEN = 32         # Chave pública X25519 raw
SALT_LEN = 16       # salt_srv
NONCE_LEN = 12      # IV_base (4B) + seq_no (8B)
SEQ_LEN = 8         # Contador monotônico 64-bit
KEY_LEN = 16        # Chave simétrica AES-128
TAG_LEN = 16        # Tag de autenticação AES-GCM
MAX_PLAINTEXT = 4096
PSS_SALT_LEN = 32   # Salt interno do RSA-PSS

# ==========================================
# CÓDIGOS DE TIPO DE FRAME
# ==========================================
class FrameType(IntEnum):
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    DATA         = 0x03
    PEER_JOINED  = 0x04
    PEER_LEFT    = 0x05
    ERROR        = 0x06

# aqui fica as exceções: ConnectionClosed sera usada quando uma conexão cair ou for encerrada. protocolerro; sera usada quando queremos encalpsular uma mensagem clara e regra de quando ela foi descumprida
class ErrorCode(IntEnum):
    FRAMING_INVALID = 0x01  # Framing inválido
    FRAME_TOO_LARGE = 0x02  # Frame grande demais
    UNKNOWN_TYPE    = 0x03  # Tipo desconhecido
    PEER_OFFLINE    = 0x04  # Destinatário offline

# ==========================================
# CÁLCULO DOS LIMITES DO FRAME DATA
# Formato: [03][nonce 12][sender 16][recipient 16][seq 8][ciphertext + tag 16]
# ==========================================
# 1B (código do tipo DATA) + NONCE_LEN (12) + sender (16) + recipient (16) + seq (8)
DATA_HEADER_LEN = 1 + NONCE_LEN + (2 * ID_LEN) + SEQ_LEN

# Plaintext mínimo = 1 byte (+ TAG_LEN)
DATA_MIN_LEN = DATA_HEADER_LEN + 1 + TAG_LEN

# Plaintext máximo = MAX_PLAINTEXT (+ TAG_LEN)
DATA_MAX_LEN = DATA_HEADER_LEN + MAX_PLAINTEXT + TAG_LEN


# ==========================================
# EXCEÇÕES DO PROTOCOLO
# ==========================================
class ConnectionClosed(Exception):
    """Disparada quando o socket fecha ou atinge EOF durante uma leitura."""
    pass


class ProtocolError(Exception):
    """
    Disparada em caso de violação das regras do protocolo.
    Carrega uma mensagem e um código numérico de erro (ErrorCode).
    
    ATENÇÃO: De acordo com a política de segurança, a mensagem NUNCA deve 
    conter chaves privadas, segredos (Z), salt, nonce ou conteúdo de mensagens.
    """
    def __init__(self, message: str, code: Optional[Union[ErrorCode, int]] = None):
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self) -> str:
        if self.code is not None:
            code_repr = self.code.name if hasattr(self.code, "name") else f"0x{self.code:02x}"
            return f"[{code_repr}] {self.message}"
        return self.message


# ==========================================
# CAMPOS VARIÁVEIS
# Formato: [2B tamanho big-endian (>H)][bytes]
# ==========================================
def pack_field(data: bytes) -> bytes:
    """Serializa um campo variável adicionando prefixo de 2 bytes big-endian (>H)."""
    if len(data) > 0xFFFF:
        raise ProtocolError("Campo excede o tamanho máximo de 65535 bytes", ErrorCode.FRAMING_INVALID)
    return struct.pack(">H", len(data)) + data


def unpack_field(buffer: bytes, offset: int = 0) -> tuple[bytes, int]:
    """
    Lê um campo variável a partir de offset em buffer.
    Retorna (dados_do_campo, novo_offset).
    Rejeita buffers truncados com ProtocolError(FRAMING_INVALID).
    """
    if offset + 2 > len(buffer):
        raise ProtocolError("Buffer insuficiente para ler tamanho do campo variável", ErrorCode.FRAMING_INVALID)

    (field_len,) = struct.unpack_from(">H", buffer, offset)
    new_offset = offset + 2 + field_len

    if new_offset > len(buffer):
        raise ProtocolError("Buffer truncado: tamanho do campo excede bytes restantes", ErrorCode.FRAMING_INVALID)

    field_data = bytes(buffer[offset + 2 : new_offset])
    return field_data, new_offset


# ==========================================
# CLIENT_HELLO (Tipo 0x01)
# Formato: [01][client_id 16][pk_C 32] -> Total 49 bytes
# ==========================================
CLIENT_HELLO_LEN = 1 + ID_LEN + PK_LEN  # 49 bytes


class ClientHello(NamedTuple):
    client_id: bytes
    pk_client: bytes


def pack_client_hello(client_id: bytes, pk_client: bytes) -> bytes:
    """
    Empacota o corpo do CLIENT_HELLO: [01][client_id 16][pk_C 32].
    Retorna exatamente 49 bytes.
    """
    if len(client_id) != ID_LEN:
        raise ProtocolError(f"client_id deve ter {ID_LEN} bytes (recebido: {len(client_id)})", ErrorCode.FRAMING_INVALID)
    if len(pk_client) != PK_LEN:
        raise ProtocolError(f"pk_client deve ter {PK_LEN} bytes (recebido: {len(pk_client)})", ErrorCode.FRAMING_INVALID)

    return bytes([FrameType.CLIENT_HELLO]) + client_id + pk_client


def parse_client_hello(data: bytes) -> ClientHello:
    """
    Desempacota o corpo do CLIENT_HELLO.
    Exige exatamente 49 bytes e tipo 0x01.
    """
    if len(data) != CLIENT_HELLO_LEN:
        raise ProtocolError(
            f"CLIENT_HELLO deve ter exatamente {CLIENT_HELLO_LEN} bytes (recebido: {len(data)})",
            ErrorCode.FRAMING_INVALID,
        )

    if data[0] != FrameType.CLIENT_HELLO:
        raise ProtocolError(
            f"Tipo inválido para CLIENT_HELLO: esperado 0x{FrameType.CLIENT_HELLO:02x}, recebido 0x{data[0]:02x}",
            ErrorCode.UNKNOWN_TYPE,
        )

    client_id = bytes(data[1 : 1 + ID_LEN])
    pk_client = bytes(data[1 + ID_LEN : 1 + ID_LEN + PK_LEN])

    return ClientHello(client_id=client_id, pk_client=pk_client)


# ==========================================
# SERVER_HELLO (Tipo 0x02)
# Formato: [02][salt_srv 16][len][pk_S][len][server.crt][len][assinatura]
# Mínimo: 1 (tipo) + 16 (salt) + 3*2 (prefixos dos campos variáveis) = 23 bytes
# ==========================================
SERVER_HELLO_MIN_LEN = 1 + SALT_LEN + (3 * 2)  # 23 bytes


class ServerHello(NamedTuple):
    salt_srv: bytes
    pk_server: bytes
    server_cert: bytes
    signature: bytes


def pack_server_hello(
    salt_srv: bytes,
    pk_server: bytes,
    server_cert: bytes,
    signature: bytes,
) -> bytes:
    """
    Empacota o corpo do SERVER_HELLO:
    [02][salt_srv 16][len][pk_S][len][server.crt][len][assinatura]
    """
    if len(salt_srv) != SALT_LEN:
        raise ProtocolError(f"salt_srv deve ter {SALT_LEN} bytes (recebido: {len(salt_srv)})", ErrorCode.FRAMING_INVALID)

    return (
        bytes([FrameType.SERVER_HELLO])
        + salt_srv
        + pack_field(pk_server)
        + pack_field(server_cert)
        + pack_field(signature)
    )


def parse_server_hello(data: bytes) -> ServerHello:
    """
    Desempacota o corpo do SERVER_HELLO.
    Exige no mínimo 23 bytes, tipo 0x02 e consumo exato de todos os bytes.
    """
    if len(data) < SERVER_HELLO_MIN_LEN:
        raise ProtocolError(
            f"SERVER_HELLO deve ter no mínimo {SERVER_HELLO_MIN_LEN} bytes (recebido: {len(data)})",
            ErrorCode.FRAMING_INVALID,
        )

    if data[0] != FrameType.SERVER_HELLO:
        raise ProtocolError(
            f"Tipo inválido para SERVER_HELLO: esperado 0x{FrameType.SERVER_HELLO:02x}, recebido 0x{data[0]:02x}",
            ErrorCode.UNKNOWN_TYPE,
        )

    salt_srv = bytes(data[1 : 1 + SALT_LEN])
    offset = 1 + SALT_LEN

    pk_server, offset = unpack_field(data, offset)
    server_cert, offset = unpack_field(data, offset)
    signature, offset = unpack_field(data, offset)

    # Exigência: o corpo deve ser consumido exatamente, sem sobra
    if offset != len(data):
        raise ProtocolError(
            f"SERVER_HELLO contém {len(data) - offset} bytes extras no final",
            ErrorCode.FRAMING_INVALID,
        )

    return ServerHello(
        salt_srv=salt_srv,
        pk_server=pk_server,
        server_cert=server_cert,
        signature=signature,
    )


# ==========================================
# HASHES CRIPTOGRÁFICOS DO PROTOCOLO
# ==========================================
def handshake_hash(
    pk_server_der: bytes,
    pk_client: bytes,
    client_id: bytes,
    salt: bytes,
) -> bytes:
    """
    H = SHA256(pk_S_der || pk_C || client_id || salt)
    Retorna 32 bytes (digest SHA-256).
    """
    if len(pk_client) != PK_LEN:
        raise ProtocolError(f"pk_client deve ter {PK_LEN} bytes (recebido: {len(pk_client)})", ErrorCode.FRAMING_INVALID)
    if len(client_id) != ID_LEN:
        raise ProtocolError(f"client_id deve ter {ID_LEN} bytes (recebido: {len(client_id)})", ErrorCode.FRAMING_INVALID)
    if len(salt) != SALT_LEN:
        raise ProtocolError(f"salt deve ter {SALT_LEN} bytes (recebido: {len(salt)})", ErrorCode.FRAMING_INVALID)

    material = pk_server_der + pk_client + client_id + salt
    return hashlib.sha256(material).digest()


def admin_hash(
    frame_type: Union[int, FrameType],
    salt_destino: bytes,
    seq: int,
    payload: bytes,
) -> bytes:
    """
    H_adm = SHA256("ADMIN" || tipo || salt_destino || seq || payload)
    O seq entra como 8 bytes big-endian (>Q).
    Retorna 32 bytes (digest SHA-256).
    """
    if len(salt_destino) != SALT_LEN:
        raise ProtocolError(f"salt_destino deve ter {SALT_LEN} bytes (recebido: {len(salt_destino)})", ErrorCode.FRAMING_INVALID)
    if seq < 0 or seq > 0xFFFFFFFFFFFFFFFF:
        raise ProtocolError(f"seq inválido para contador de 64 bits: {seq}", ErrorCode.FRAMING_INVALID)

    tipo_byte = bytes([int(frame_type)])
    seq_bytes = struct.pack(">Q", seq)

    material = b"ADMIN" + tipo_byte + salt_destino + seq_bytes + payload
    return hashlib.sha256(material).digest()


# ==========================================
# ASSINATURAS RSA-PSS
# PSS com MGF1(SHA256), salt_length=32 e hash SHA256.
# H é passado como mensagem direta (sem Prehashed).
# ==========================================
def public_key_der(public_key: rsa.RSAPublicKey) -> bytes:
    """Exporta chave pública RSA no formato binário DER (SubjectPublicKeyInfo)."""
    if hasattr(public_key, "public_key"):
        public_key = public_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def sign_digest(private_key: rsa.RSAPrivateKey, digest_h: bytes) -> bytes:
    """
    Assina o digest H com RSA-PSS sobre SHA256 (MGF1-SHA256, salt_length=32).
    H é tratado diretamente como a mensagem (o PSS aplica SHA-256 por dentro).
    """
    pss_padding = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=PSS_SALT_LEN,
    )
    return private_key.sign(
        digest_h,
        pss_padding,
        hashes.SHA256(),
    )


def verify_digest(
    public_key: Union[rsa.RSAPublicKey, bytes],
    signature: bytes,
    digest_h: bytes,
) -> bool:
    """
    Verifica a assinatura RSA-PSS de digest_h.
    Aceita o objeto RSAPublicKey ou bytes DER.
    Retorna True se válida, False se inválida (sem propagar InvalidSignature).
    """
    try:
        if isinstance(public_key, (bytes, bytearray)):
            pub_obj = serialization.load_der_public_key(public_key)
        else:
            pub_obj = public_key

        pss_padding = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=PSS_SALT_LEN,
        )
        pub_obj.verify(
            signature,
            digest_h,
            pss_padding,
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    except Exception:
        return False


# ==========================================
# MENSAGENS ADMINISTRATIVAS (PEER_JOINED, PEER_LEFT, ERROR)
# ==========================================
PEER_JOINED_PAYLOAD_LEN = ID_LEN + PK_LEN + SALT_LEN  # 16 + 32 + 16 = 64 bytes
PEER_LEFT_PAYLOAD_LEN = ID_LEN                        # 16 bytes
ERROR_PAYLOAD_LEN = 1                                 # 1 byte

ADMIN_PAYLOAD_SIZES = {
    FrameType.PEER_JOINED: PEER_JOINED_PAYLOAD_LEN,
    FrameType.PEER_LEFT: PEER_LEFT_PAYLOAD_LEN,
    FrameType.ERROR: ERROR_PAYLOAD_LEN,
}


class AdminMessage(NamedTuple):
    type: int
    payload: bytes
    seq: int
    signature: bytes


def build_peer_joined_payload(client_id: bytes, pk_client: bytes, peer_salt: bytes) -> bytes:
    """Constrói payload de PEER_JOINED: [client_id 16][pk_C 32][salt_do_peer 16] (64 bytes)."""
    if len(client_id) != ID_LEN:
        raise ProtocolError(f"client_id deve ter {ID_LEN} bytes (recebido: {len(client_id)})", ErrorCode.FRAMING_INVALID)
    if len(pk_client) != PK_LEN:
        raise ProtocolError(f"pk_client deve ter {PK_LEN} bytes (recebido: {len(pk_client)})", ErrorCode.FRAMING_INVALID)
    if len(peer_salt) != SALT_LEN:
        raise ProtocolError(f"peer_salt deve ter {SALT_LEN} bytes (recebido: {len(peer_salt)})", ErrorCode.FRAMING_INVALID)

    return client_id + pk_client + peer_salt


def build_peer_left_payload(client_id: bytes) -> bytes:
    """Constrói payload de PEER_LEFT: [client_id 16] (16 bytes)."""
    if len(client_id) != ID_LEN:
        raise ProtocolError(f"client_id deve ter {ID_LEN} bytes (recebido: {len(client_id)})", ErrorCode.FRAMING_INVALID)
    return client_id


def build_error_payload(error_code: Union[int, ErrorCode]) -> bytes:
    """Constrói payload de ERROR: [código 1] (1 byte)."""
    code_val = int(error_code)
    if not (0 <= code_val <= 255):
        raise ProtocolError(f"Código de erro inválido para 1 byte: {code_val}", ErrorCode.FRAMING_INVALID)
    return bytes([code_val])


def pack_admin(
    frame_type: Union[int, FrameType],
    payload: bytes,
    seq: int,
    signature: bytes,
) -> bytes:
    """
    Empacota o corpo de uma mensagem administrativa:
    [1B tipo][payload][seq 8B (>Q)][len 2B][assinatura]
    """
    tipo_int = int(frame_type)
    expected_len = ADMIN_PAYLOAD_SIZES.get(tipo_int)
    if expected_len is None:
        raise ProtocolError(f"Tipo desconhecido para mensagem administrativa: {tipo_int}", ErrorCode.UNKNOWN_TYPE)

    if len(payload) != expected_len:
        raise ProtocolError(
            f"Payload de tipo 0x{tipo_int:02x} deve ter {expected_len} bytes (recebido: {len(payload)})",
            ErrorCode.FRAMING_INVALID,
        )

    if not (0 <= seq <= 0xFFFFFFFFFFFFFFFF):
        raise ProtocolError(f"Contador seq inválido para 64 bits: {seq}", ErrorCode.FRAMING_INVALID)

    return (
        bytes([tipo_int])
        + payload
        + struct.pack(">Q", seq)
        + pack_field(signature)
    )


def parse_admin(data: bytes) -> AdminMessage:
    """
    Desempacota o corpo de uma mensagem administrativa.
    Identifica tamanho pelo tipo, lê seq e assinatura, e exige consumo exato do buffer.
    Não verifica a assinatura.
    """
    if len(data) < 1:
        raise ProtocolError("Buffer vazio para mensagem administrativa", ErrorCode.FRAMING_INVALID)

    frame_type = data[0]
    expected_len = ADMIN_PAYLOAD_SIZES.get(frame_type)
    if expected_len is None:
        raise ProtocolError(f"Tipo não administrativo ou desconhecido: 0x{frame_type:02x}", ErrorCode.UNKNOWN_TYPE)

    # Mínimo: 1 (tipo) + expected_len + 8 (seq) + 2 (tamanho do campo de assinatura)
    min_len = 1 + expected_len + SEQ_LEN + 2
    if len(data) < min_len:
        raise ProtocolError(
            f"Tamanho insuficiente para frame administrativo (esperado no mínimo {min_len}, recebido {len(data)})",
            ErrorCode.FRAMING_INVALID,
        )

    payload_start = 1
    payload_end = payload_start + expected_len
    payload = bytes(data[payload_start:payload_end])

    seq_start = payload_end
    seq_end = seq_start + SEQ_LEN
    (seq,) = struct.unpack(">Q", data[seq_start:seq_end])

    signature, final_offset = unpack_field(data, seq_end)

    if final_offset != len(data):
        raise ProtocolError(
            f"Frame administrativo contém {len(data) - final_offset} bytes extras no final",
            ErrorCode.FRAMING_INVALID,
        )

    return AdminMessage(type=frame_type, payload=payload, seq=seq, signature=signature)


# ==========================================
# DATA (Tipo 0x03) - Criptografia Ponta-a-Ponta (E2E)
# Formato: [03][nonce 12][sender 16][recipient 16][seq 8][ciphertext+tag 16]
# Limites: DATA_MIN_LEN (70) até DATA_MAX_LEN (4165)
# ==========================================
AAD_LEN = (2 * ID_LEN) + SEQ_LEN  # 16 + 16 + 8 = 40 bytes


class DataMessage(NamedTuple):
    nonce: bytes
    sender_id: bytes
    recipient_id: bytes
    seq: int
    ciphertext_and_tag: bytes


def build_nonce(iv_base: bytes, seq_no: int) -> bytes:
    """Constrói nonce de 12 bytes: IV_base (4B) || seq_no (8B big-endian)."""
    if len(iv_base) != 4:
        raise ProtocolError(f"IV_base deve ter 4 bytes (recebido: {len(iv_base)})", ErrorCode.FRAMING_INVALID)
    if not (0 <= seq_no <= 0xFFFFFFFFFFFFFFFF):
        raise ProtocolError(f"seq_no inválido para 64 bits: {seq_no}", ErrorCode.FRAMING_INVALID)
    return iv_base + struct.pack(">Q", seq_no)


def build_aad(sender_id: bytes, recipient_id: bytes, seq_no: int) -> bytes:
    """Constrói AAD de 40 bytes: sender_id (16B) || recipient_id (16B) || seq_no (8B big-endian)."""
    if len(sender_id) != ID_LEN:
        raise ProtocolError(f"sender_id deve ter {ID_LEN} bytes (recebido: {len(sender_id)})", ErrorCode.FRAMING_INVALID)
    if len(recipient_id) != ID_LEN:
        raise ProtocolError(f"recipient_id deve ter {ID_LEN} bytes (recebido: {len(recipient_id)})", ErrorCode.FRAMING_INVALID)
    if not (0 <= seq_no <= 0xFFFFFFFFFFFFFFFF):
        raise ProtocolError(f"seq_no inválido para 64 bits: {seq_no}", ErrorCode.FRAMING_INVALID)
    return sender_id + recipient_id + struct.pack(">Q", seq_no)


def pack_data(
    nonce: bytes,
    sender_id: bytes,
    recipient_id: bytes,
    seq_no: int,
    ciphertext_and_tag: bytes,
) -> bytes:
    """
    Empacota o corpo do frame DATA:
    [03][nonce 12][sender 16][recipient 16][seq 8][ciphertext+tag]
    Valida tamanho entre DATA_MIN_LEN (70) e DATA_MAX_LEN (4165).
    """
    if len(nonce) != NONCE_LEN:
        raise ProtocolError(f"nonce deve ter {NONCE_LEN} bytes (recebido: {len(nonce)})", ErrorCode.FRAMING_INVALID)
    if len(sender_id) != ID_LEN:
        raise ProtocolError(f"sender_id deve ter {ID_LEN} bytes (recebido: {len(sender_id)})", ErrorCode.FRAMING_INVALID)
    if len(recipient_id) != ID_LEN:
        raise ProtocolError(f"recipient_id deve ter {ID_LEN} bytes (recebido: {len(recipient_id)})", ErrorCode.FRAMING_INVALID)
    if not (0 <= seq_no <= 0xFFFFFFFFFFFFFFFF):
        raise ProtocolError(f"seq_no inválido para 64 bits: {seq_no}", ErrorCode.FRAMING_INVALID)

    body = (
        bytes([FrameType.DATA])
        + nonce
        + sender_id
        + recipient_id
        + struct.pack(">Q", seq_no)
        + ciphertext_and_tag
    )

    if len(body) < DATA_MIN_LEN or len(body) > DATA_MAX_LEN:
        raise ProtocolError(
            f"Tamanho do frame DATA inválido: {len(body)} (permitido: {DATA_MIN_LEN} a {DATA_MAX_LEN})",
            ErrorCode.FRAMING_INVALID if len(body) < DATA_MIN_LEN else ErrorCode.FRAME_TOO_LARGE,
        )

    return body


def parse_data(data: bytes) -> DataMessage:
    """
    Desempacota o corpo do frame DATA.
    Valida tamanho entre 70 e 4165 e tipo 0x03.
    """
    if len(data) < DATA_MIN_LEN or len(data) > DATA_MAX_LEN:
        raise ProtocolError(
            f"Tamanho do frame DATA fora dos limites: {len(data)} (esperado entre {DATA_MIN_LEN} e {DATA_MAX_LEN})",
            ErrorCode.FRAMING_INVALID if len(data) < DATA_MIN_LEN else ErrorCode.FRAME_TOO_LARGE,
        )

    if data[0] != FrameType.DATA:
        raise ProtocolError(
            f"Tipo inválido para DATA: esperado 0x{FrameType.DATA:02x}, recebido 0x{data[0]:02x}",
            ErrorCode.UNKNOWN_TYPE,
        )

    nonce = bytes(data[1 : 1 + NONCE_LEN])
    sender_start = 1 + NONCE_LEN
    recipient_start = sender_start + ID_LEN
    seq_start = recipient_start + ID_LEN
    ciphertext_start = seq_start + SEQ_LEN

    sender_id = bytes(data[sender_start:recipient_start])
    recipient_id = bytes(data[recipient_start:seq_start])
    (seq_no,) = struct.unpack(">Q", data[seq_start:ciphertext_start])
    ciphertext_and_tag = bytes(data[ciphertext_start:])

    return DataMessage(
        nonce=nonce,
        sender_id=sender_id,
        recipient_id=recipient_id,
        seq=seq_no,
        ciphertext_and_tag=ciphertext_and_tag,
    )


def peek_ids(data: bytes) -> tuple[bytes, bytes]:
    """
    Lê apenas sender_id e recipient_id do frame DATA sem decifrar nem copiar o ciphertext.
    Valida tamanho entre 70 e 4165 e tipo 0x03.
    Retorna (sender_id, recipient_id).
    """
    if len(data) < DATA_MIN_LEN or len(data) > DATA_MAX_LEN:
        raise ProtocolError(
            f"Tamanho do frame DATA fora dos limites: {len(data)} (esperado entre {DATA_MIN_LEN} e {DATA_MAX_LEN})",
            ErrorCode.FRAMING_INVALID if len(data) < DATA_MIN_LEN else ErrorCode.FRAME_TOO_LARGE,
        )

    if data[0] != FrameType.DATA:
        raise ProtocolError(
            f"Tipo inválido para DATA: esperado 0x{FrameType.DATA:02x}, recebido 0x{data[0]:02x}",
            ErrorCode.UNKNOWN_TYPE,
        )

    sender_start = 1 + NONCE_LEN
    recipient_start = sender_start + ID_LEN
    recipient_end = recipient_start + ID_LEN

    sender_id = bytes(data[sender_start:recipient_start])
    recipient_id = bytes(data[recipient_start:recipient_end])

    return sender_id, recipient_id


# ==========================================
# PAPÉIS DO PAR E SALT DE SESSÃO E2E
# A é o menor client_id (comparação byte a byte). salt_par é o salt_srv do A.
# ==========================================
def i_am_a(my_id: bytes, peer_id: bytes) -> bool:
    """
    Determina se este cliente é o participante 'A' na sessão com o peer.
    'A' é quem possui o menor client_id na comparação byte a byte.
    Dispara ProtocolError se my_id == peer_id.
    """
    if len(my_id) != ID_LEN:
        raise ProtocolError(f"my_id deve ter {ID_LEN} bytes (recebido: {len(my_id)})", ErrorCode.FRAMING_INVALID)
    if len(peer_id) != ID_LEN:
        raise ProtocolError(f"peer_id deve ter {ID_LEN} bytes (recebido: {len(peer_id)})", ErrorCode.FRAMING_INVALID)

    if my_id == peer_id:
        raise ProtocolError("client_id próprio e do peer não podem ser iguais", ErrorCode.FRAMING_INVALID)

    return my_id < peer_id


def pair_salt(
    my_id: bytes,
    peer_id: bytes,
    my_salt: bytes,
    peer_salt: bytes,
) -> bytes:
    """
    Retorna o salt compartilhado da sessão E2E (salt_par).
    Por definição do protocolo, salt_par é o salt_srv do cliente com menor ID ('A').
    """
    if len(my_salt) != SALT_LEN:
        raise ProtocolError(f"my_salt deve ter {SALT_LEN} bytes (recebido: {len(my_salt)})", ErrorCode.FRAMING_INVALID)
    if len(peer_salt) != SALT_LEN:
        raise ProtocolError(f"peer_salt deve ter {SALT_LEN} bytes (recebido: {len(peer_salt)})", ErrorCode.FRAMING_INVALID)

    return my_salt if i_am_a(my_id, peer_id) else peer_salt


# ==========================================
# FINGERPRINT (LOGS E IDENTIFICAÇÃO)
# Primeiros 16 caracteres hexadecimais do SHA-256 da chave pública
# ==========================================
def fingerprint(pk: bytes) -> str:
    """
    Calcula o fingerprint da chave pública: primeiros 16 caracteres hexadecimais do SHA-256.
    Seguro para uso em logs e verificação visual entre clientes.
    """
    if hasattr(pk, "public_bytes_raw"):
        # Objeto X25519PublicKey
        pk_bytes = pk.public_bytes_raw()
    elif hasattr(pk, "public_bytes"):
        # Objeto RSAPublicKey (DER SubjectPublicKeyInfo)
        pk_bytes = public_key_der(pk)
    else:
        pk_bytes = bytes(pk)

    digest = hashlib.sha256(pk_bytes).hexdigest()
    return digest[:16]










#funções encode_frame: valida se o tamanho esta dentro dos limites; send_frame: escreve o frame do socket e aguarda o envio; 
#frame e recv_frame: 
class Frame(NamedTuple):
    type: int
    payload: bytes

    @property
    def body(self) -> bytes:
        """Corpo completo do frame (tipo + campos)."""
        return bytes([self.type]) + self.payload


def encode_frame(frame_type: Union[int, FrameType, bytes], payload: bytes = b"") -> bytes:
    """
    Empacota um frame com prefixo de tamanho de 4 bytes big-endian.
    Aceita (frame_type, payload) ou bytes já contendo [tipo + campos].
    """
    if isinstance(frame_type, (bytes, bytearray)):
        body = bytes(frame_type)
    else:
        body = bytes([int(frame_type)]) + payload

    n = len(body)
    if n == 0:
        raise ProtocolError("Tamanho do frame não pode ser 0", ErrorCode.FRAMING_INVALID)
    if n > MAX_FRAME:
        raise ProtocolError(
            f"Frame excede tamanho máximo ({n} > {MAX_FRAME})",
            ErrorCode.FRAME_TOO_LARGE,
        )

    return struct.pack(">I", n) + body


async def send_frame(
    writer: asyncio.StreamWriter,
    frame_type_or_bytes: Union[int, FrameType, bytes],
    payload: bytes = b"",
) -> None:
    """Envia um frame no formato [4B tamanho big-endian][1B tipo][campos]."""
    try:
        if isinstance(frame_type_or_bytes, (bytes, bytearray)) and payload == b"":
            # Se já for um frame pré-codificado com prefixo de 4 bytes correspondente
            if len(frame_type_or_bytes) >= 4:
                (expected_len,) = struct.unpack(">I", frame_type_or_bytes[:4])
                if expected_len == len(frame_type_or_bytes) - 4:
                    raw_data = bytes(frame_type_or_bytes)
                else:
                    raw_data = encode_frame(frame_type_or_bytes)
            else:
                raw_data = encode_frame(frame_type_or_bytes)
        else:
            raw_data = encode_frame(frame_type_or_bytes, payload)

        writer.write(raw_data)
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError) as e:
        raise ConnectionClosed("Conexão perdida durante envio do frame") from e


async def recv_frame(reader: asyncio.StreamReader) -> Frame:
    """
    Lê o prefixo de 4 bytes, valida o tamanho antes de ler o corpo,
    e lê exatamente n bytes. Converte IncompleteReadError em ConnectionClosed.
    """
    # 1. Lê os 4 bytes do tamanho do frame
    try:
        len_bytes = await reader.readexactly(4)
    except asyncio.IncompleteReadError as e:
        raise ConnectionClosed("Conexão encerrada durante leitura do tamanho do frame") from e
    except (ConnectionResetError, BrokenPipeError) as e:
        raise ConnectionClosed("Conexão perdida durante leitura do tamanho do frame") from e

    (n,) = struct.unpack(">I", len_bytes)

    # 2. Valida o tamanho ANTES de alocar/ler o corpo
    if n == 0:
        raise ProtocolError("Tamanho do frame inválido (0)", ErrorCode.FRAMING_INVALID)
    if n > MAX_FRAME:
        raise ProtocolError(
            f"Frame excede MAX_FRAME ({n} > {MAX_FRAME})",
            ErrorCode.FRAME_TOO_LARGE,
        )

    # 3. Lê exatamente n bytes do corpo
    try:
        body = await reader.readexactly(n)
    except asyncio.IncompleteReadError as e:
        raise ConnectionClosed("Conexão truncada durante leitura do corpo do frame") from e
    except (ConnectionResetError, BrokenPipeError) as e:
        raise ConnectionClosed("Conexão perdida durante leitura do corpo do frame") from e

    frame_type = body[0]
    payload = bytes(body[1:])
    return Frame(type=frame_type, payload=payload)



if __name__ == "__main__":
    print(f"DATA_HEADER_LEN: {DATA_HEADER_LEN}")
    print(f"DATA_MIN_LEN:    {DATA_MIN_LEN}")
    print(f"DATA_MAX_LEN:    {DATA_MAX_LEN}")

    # Teste das exceções
    err = ProtocolError("Framing inválido recebido", ErrorCode.FRAMING_INVALID)
    assert isinstance(err, Exception)
    assert err.code == ErrorCode.FRAMING_INVALID
    assert str(err) == "[FRAMING_INVALID] Framing inválido recebido"

    closed = ConnectionClosed("Conexão fechada pelo peer")
    assert isinstance(closed, Exception)
    print("Testes de exceções: OK")

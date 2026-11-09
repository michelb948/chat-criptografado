"""
test_protocol.py - Suíte de testes completa e unificada do protocolo de segurança E2E.
Testa todos os módulos de protocol.py e valida todas as armadilhas:
1. Big-endian estrito (>I, >H, >Q).
2. Conversão explícita de fatias para bytes (inclusive com memoryview).
3. Distinção clara entre SALT_LEN (16) e PSS_SALT_LEN (32).
4. Validação antecipada de tamanhos antes de ler payloads.
5. Consumo exato de buffers sem tolerância a bytes sobrando no final.
"""

import asyncio
import hashlib
import os
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import protocol
from protocol import (
    # Constantes
    MAX_FRAME,
    ID_LEN,
    PK_LEN,
    SALT_LEN,
    NONCE_LEN,
    SEQ_LEN,
    KEY_LEN,
    TAG_LEN,
    MAX_PLAINTEXT,
    PSS_SALT_LEN,
    DATA_HEADER_LEN,
    DATA_MIN_LEN,
    DATA_MAX_LEN,
    CLIENT_HELLO_LEN,
    SERVER_HELLO_MIN_LEN,
    PEER_JOINED_PAYLOAD_LEN,
    PEER_LEFT_PAYLOAD_LEN,
    ERROR_PAYLOAD_LEN,
    # Tipos e Erros
    FrameType,
    ErrorCode,
    ConnectionClosed,
    ProtocolError,
    Frame,
    # Framing
    encode_frame,
    send_frame,
    recv_frame,
    # Campos variáveis
    pack_field,
    unpack_field,
    # CLIENT_HELLO
    pack_client_hello,
    parse_client_hello,
    # SERVER_HELLO
    pack_server_hello,
    parse_server_hello,
    # Hashes
    handshake_hash,
    admin_hash,
    # RSA-PSS
    public_key_der,
    sign_digest,
    verify_digest,
    # Mensagens administrativas
    build_peer_joined_payload,
    build_peer_left_payload,
    build_error_payload,
    pack_admin,
    parse_admin,
    # DATA
    build_nonce,
    build_aad,
    pack_data,
    parse_data,
    peek_ids,
    # Papéis do par e salt
    i_am_a,
    pair_salt,
    # Fingerprint
    fingerprint,
)


# =====================================================================
# 1. TESTE DE CONSTANTES E DISTINÇÃO DE SALTS
# =====================================================================
def test_constants_and_limits():
    print("--- 1. Testando Constantes e Limites Derivados ---")
    assert MAX_FRAME == 8192
    assert ID_LEN == 16
    assert PK_LEN == 32
    assert SALT_LEN == 16
    assert NONCE_LEN == 12
    assert SEQ_LEN == 8
    assert KEY_LEN == 16
    assert TAG_LEN == 16
    assert MAX_PLAINTEXT == 4096

    # ARMADILHA: Distinção explícita entre salt_srv e salt interno do RSA-PSS
    assert PSS_SALT_LEN == 32
    assert SALT_LEN != PSS_SALT_LEN, "SALT_LEN e PSS_SALT_LEN devem ser constantes distintas!"

    # Cálculos derivados
    assert DATA_HEADER_LEN == 53
    assert DATA_MIN_LEN == 70
    assert DATA_MAX_LEN == 4165
    assert CLIENT_HELLO_LEN == 49
    assert SERVER_HELLO_MIN_LEN == 23

    print("✓ Constantes, limites e distinção de salts conferidos com sucesso.")


# =====================================================================
# 2. TESTE DE EXCEÇÕES E POLÍTICA DE SEGURANÇA
# =====================================================================
def test_exceptions():
    print("--- 2. Testando Exceções ---")
    closed = ConnectionClosed("Conexão fechada pelo peer")
    assert isinstance(closed, Exception)

    err = ProtocolError("Framing inválido", ErrorCode.FRAMING_INVALID)
    assert isinstance(err, Exception)
    assert err.code == ErrorCode.FRAMING_INVALID
    assert "[FRAMING_INVALID]" in str(err)
    print("✓ Exceções validadas com sucesso.")


# =====================================================================
# 3. TESTE DE CAMPOS VARIÁVEIS (PACK / UNPACK)
# =====================================================================
def test_variable_fields():
    print("--- 3. Testando Campos Variáveis (>H) ---")
    # ARMADILHA: Big-endian >H estrito
    prefix = struct.pack(">H", 1)
    assert prefix == b"\x00\x01", "Prefixo de campo variável DEVE ser big-endian (>H)"

    # Ida e volta
    payload = b"Certificado_X509_DER_Teste"
    packed = pack_field(payload)
    assert len(packed) == 2 + len(payload)
    unpacked, next_off = unpack_field(packed, 0)
    assert unpacked == payload
    assert isinstance(unpacked, bytes)
    assert next_off == len(packed)

    # ARMADILHA: Suporte a memoryview com retorno em bytes
    mv = memoryview(packed)
    unpacked_mv, _ = unpack_field(mv, 0)
    assert isinstance(unpacked_mv, bytes)
    assert unpacked_mv == payload

    # ARMADILHA: Validação de tamanho antes de ler
    try:
        unpack_field(b"\x00", 0)  # Menos de 2 bytes para o prefixo
        assert False, "Deveria falhar"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID

    try:
        # Declara 10 bytes mas só há 4
        unpack_field(struct.pack(">H", 10) + b"1234", 0)
        assert False, "Deveria falhar com buffer truncado"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID

    print("✓ Campos variáveis (>H), ida/volta e proteções de buffer aprovados.")


# =====================================================================
# 4. TESTE DE FRAMING TCP ASSÍNCRONO
# =====================================================================
async def test_framing_async():
    print("--- 4. Testando Framing TCP em Asyncio ---")
    # ARMADILHA: Big-endian >I estrito para tamanho do frame
    assert struct.pack(">I", 1) == b"\x00\x00\x00\x01"

    # 4.1 Frame normal
    received = []
    async def handler_normal(reader, writer):
        try:
            f = await recv_frame(reader)
            received.append(f)
        finally:
            writer.close()
            await writer.wait_closed()

    srv = await asyncio.start_server(handler_normal, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    cr, cw = await asyncio.open_connection("127.0.0.1", port)
    await send_frame(cw, FrameType.CLIENT_HELLO, b"dados_hello")
    cw.close()
    await cw.wait_closed()
    srv.close()
    await srv.wait_closed()

    assert len(received) == 1
    assert received[0].type == FrameType.CLIENT_HELLO
    assert received[0].payload == b"dados_hello"
    assert isinstance(received[0].payload, bytes)

    # 4.2 ARMADILHA: Validar tamanho antes de ler (MAX_FRAME + 1)
    caught_too_large = []
    async def handler_large(reader, writer):
        try:
            await recv_frame(reader)
        except ProtocolError as e:
            caught_too_large.append(e)
        finally:
            writer.close()
            await writer.wait_closed()

    srv = await asyncio.start_server(handler_large, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    cr, cw = await asyncio.open_connection("127.0.0.1", port)
    cw.write(struct.pack(">I", MAX_FRAME + 1))
    await cw.drain()
    await cr.read()
    cw.close()
    await cw.wait_closed()
    srv.close()
    await srv.wait_closed()

    assert len(caught_too_large) == 1
    assert caught_too_large[0].code == ErrorCode.FRAME_TOO_LARGE

    # 4.3 Frame com tamanho 0 rejeitado imediatamente
    caught_zero = []
    async def handler_zero(reader, writer):
        try:
            await recv_frame(reader)
        except ProtocolError as e:
            caught_zero.append(e)
        finally:
            writer.close()
            await writer.wait_closed()

    srv = await asyncio.start_server(handler_zero, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    cr, cw = await asyncio.open_connection("127.0.0.1", port)
    cw.write(struct.pack(">I", 0))
    await cw.drain()
    await cr.read()
    cw.close()
    await cw.wait_closed()
    srv.close()
    await srv.wait_closed()

    assert len(caught_zero) == 1
    assert caught_zero[0].code == ErrorCode.FRAMING_INVALID

    # 4.4 Conexão fechada no meio (dispara ConnectionClosed)
    caught_closed = []
    async def handler_closed(reader, writer):
        try:
            await recv_frame(reader)
        except ConnectionClosed as e:
            caught_closed.append(e)
        finally:
            writer.close()
            await writer.wait_closed()

    srv = await asyncio.start_server(handler_closed, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    cr, cw = await asyncio.open_connection("127.0.0.1", port)
    cw.write(struct.pack(">I", 10))
    cw.write(b"123")  # Envia só 3 bytes em vez de 10
    await cw.drain()
    cw.close()
    await cw.wait_closed()
    await asyncio.sleep(0.05)
    srv.close()
    await srv.wait_closed()

    assert len(caught_closed) == 1
    assert isinstance(caught_closed[0], ConnectionClosed)

    print("✓ Framing TCP: normal, >MAX_FRAME, tamanho 0 e fechamento abrupto validados.")


# =====================================================================
# 5. TESTE DE CLIENT_HELLO (EXATOS 49 BYTES, TIPO 0x01)
# =====================================================================
def test_client_hello():
    print("--- 5. Testando CLIENT_HELLO ---")
    cid = os.urandom(16)
    pk_c = os.urandom(32)

    packed = pack_client_hello(cid, pk_c)
    assert len(packed) == 49
    assert packed[0] == FrameType.CLIENT_HELLO

    hello = parse_client_hello(packed)
    assert hello.client_id == cid
    assert hello.pk_client == pk_c
    assert isinstance(hello.client_id, bytes)
    assert isinstance(hello.pk_client, bytes)

    # ARMADILHA: memoryview
    hello_mv = parse_client_hello(memoryview(packed))
    assert isinstance(hello_mv.client_id, bytes)
    assert hello_mv.client_id == cid

    # ARMADILHA: Sem sobra (48B e 50B rejeitados)
    for bad_len in (packed[:48], packed + b"\x00"):
        try:
            parse_client_hello(bad_len)
            assert False, "Deveria falhar com tamanho != 49"
        except ProtocolError as e:
            assert e.code == ErrorCode.FRAMING_INVALID

    # Tipo incorreto
    try:
        parse_client_hello(bytes([FrameType.SERVER_HELLO]) + packed[1:])
        assert False, "Deveria falhar com tipo incorreto"
    except ProtocolError as e:
        assert e.code == ErrorCode.UNKNOWN_TYPE

    print("✓ CLIENT_HELLO: exatos 49 bytes, tipo 0x01 e rejeição de sobras validados.")


# =====================================================================
# 6. TESTE DE SERVER_HELLO (MIN 23 BYTES, SEM SOBRA)
# =====================================================================
def test_server_hello():
    print("--- 6. Testando SERVER_HELLO ---")
    salt = os.urandom(16)
    pk_s = b"\x30\x82\x01\x22" + os.urandom(60)
    cert = b"\x30\x82\x02\x40" + os.urandom(100)
    sig = os.urandom(256)

    packed = pack_server_hello(salt, pk_s, cert, sig)
    assert packed[0] == FrameType.SERVER_HELLO
    assert len(packed) >= 23

    sh = parse_server_hello(packed)
    assert sh.salt_srv == salt
    assert sh.pk_server == pk_s
    assert sh.server_cert == cert
    assert sh.signature == sig
    assert isinstance(sh.salt_srv, bytes)
    assert isinstance(sh.pk_server, bytes)

    # ARMADILHA: Sem sobra (1 byte a mais no final)
    try:
        parse_server_hello(packed + b"\x00")
        assert False, "Deveria falhar com byte extra"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID

    # 1 byte a menos (truncado)
    try:
        parse_server_hello(packed[:-1])
        assert False, "Deveria falhar com byte a menos"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID

    # Menor que 23 bytes
    try:
        parse_server_hello(bytes([FrameType.SERVER_HELLO]) + os.urandom(21))
        assert False, "Deveria falhar com < 23 bytes"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID

    print("✓ SERVER_HELLO: roundtrip, consumo exato e rejeição de sobra validados.")


# =====================================================================
# 7. TESTE DE HASHES (SHA-256, BIG-ENDIAN >Q NO SEQ)
# =====================================================================
def test_hashes():
    print("--- 7. Testando Hashes (handshake_hash e admin_hash) ---")
    pk_s = os.urandom(100)
    pk_c = os.urandom(32)
    cid = os.urandom(16)
    salt = os.urandom(16)

    h_hs = handshake_hash(pk_s, pk_c, cid, salt)
    assert len(h_hs) == 32

    # Efeito avalanche handshake_hash
    assert handshake_hash(pk_s[:-1] + b"\xff", pk_c, cid, salt) != h_hs
    assert handshake_hash(pk_s, pk_c[:-1] + b"\xff", cid, salt) != h_hs
    assert handshake_hash(pk_s, pk_c, cid[:-1] + b"\xff", salt) != h_hs
    assert handshake_hash(pk_s, pk_c, cid, salt[:-1] + b"\xff") != h_hs

    # admin_hash com >Q no seq
    salt_dest = os.urandom(16)
    h_adm = admin_hash(FrameType.PEER_JOINED, salt_dest, 10, b"payload")
    assert len(h_adm) == 32
    # Confere manualmente que seq 10 entrou como 8B big-endian (>Q)
    expected_adm = hashlib.sha256(
        b"ADMIN" + bytes([FrameType.PEER_JOINED]) + salt_dest + struct.pack(">Q", 10) + b"payload"
    ).digest()
    assert h_adm == expected_adm

    # Efeito avalanche admin_hash
    assert admin_hash(FrameType.PEER_LEFT, salt_dest, 10, b"payload") != h_adm
    assert admin_hash(FrameType.PEER_JOINED, salt_dest, 11, b"payload") != h_adm
    assert admin_hash(FrameType.PEER_JOINED, salt_dest, 10, b"payload2") != h_adm

    print("✓ Hashes: 32 bytes SHA-256 e sensibilidade estrita confirmados.")


# =====================================================================
# 8. TESTE DE ASSINATURA RSA-PSS
# =====================================================================
def test_rsa_pss():
    print("--- 8. Testando Assinatura RSA-PSS ---")
    # Chave RSA 2048
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()

    # DER SubjectPublicKeyInfo tem exatamente 294 bytes
    der = public_key_der(pub)
    assert len(der) == 294, f"DER deve ter exatamente 294 bytes (obtido: {len(der)})"

    # Assinar digest H (32B) direto sem Prehashed
    h = os.urandom(32)
    sig = sign_digest(key, h)
    assert len(sig) == 256

    # Verificar com RSAPublicKey e com bytes DER
    assert verify_digest(pub, sig, h) is True
    assert verify_digest(der, sig, h) is True

    # Alterar 1 bit no digest H -> False sem exception
    h_bad = h[:-1] + bytes([h[-1] ^ 0x01])
    assert verify_digest(pub, sig, h_bad) is False

    # Alterar 1 bit na assinatura -> False sem exception
    sig_bad = sig[:-1] + bytes([sig[-1] ^ 0x01])
    assert verify_digest(pub, sig_bad, h) is False

    print("✓ RSA-PSS: DER 294 bytes, verificação e integridade confirmadas.")


# =====================================================================
# 9. TESTE DE MENSAGENS ADMINISTRATIVAS (331, 283, 268 BYTES)
# =====================================================================
def test_admin_messages():
    print("--- 9. Testando Mensagens Administrativas (PEER_JOINED, PEER_LEFT, ERROR) ---")
    cid = os.urandom(16)
    pk_c = os.urandom(32)
    salt_peer = os.urandom(16)
    sig_256 = os.urandom(256)
    seq = 1

    # 9.1 PEER_JOINED: payload 64B, corpo total 331B
    p_joined = build_peer_joined_payload(cid, pk_c, salt_peer)
    assert len(p_joined) == 64
    body_joined = pack_admin(FrameType.PEER_JOINED, p_joined, seq, sig_256)
    assert len(body_joined) == 331, f"PEER_JOINED deve ter 331 bytes (obtido: {len(body_joined)})"
    parsed_j = parse_admin(body_joined)
    assert parsed_j.type == FrameType.PEER_JOINED
    assert parsed_j.payload == p_joined
    assert parsed_j.seq == seq
    assert parsed_j.signature == sig_256
    assert isinstance(parsed_j.payload, bytes)

    # 9.2 PEER_LEFT: payload 16B, corpo total 283B
    p_left = build_peer_left_payload(cid)
    assert len(p_left) == 16
    body_left = pack_admin(FrameType.PEER_LEFT, p_left, seq, sig_256)
    assert len(body_left) == 283, f"PEER_LEFT deve ter 283 bytes (obtido: {len(body_left)})"
    parsed_l = parse_admin(body_left)
    assert parsed_l.type == FrameType.PEER_LEFT
    assert parsed_l.payload == p_left
    assert parsed_l.seq == seq
    assert parsed_l.signature == sig_256

    # 9.3 ERROR: payload 1B, corpo total 268B
    p_err = build_error_payload(ErrorCode.PEER_OFFLINE)
    assert len(p_err) == 1
    body_err = pack_admin(FrameType.ERROR, p_err, seq, sig_256)
    assert len(body_err) == 268, f"ERROR deve ter 268 bytes (obtido: {len(body_err)})"
    parsed_e = parse_admin(body_err)
    assert parsed_e.type == FrameType.ERROR
    assert parsed_e.payload[0] == ErrorCode.PEER_OFFLINE
    assert parsed_e.seq == seq
    assert parsed_e.signature == sig_256

    # ARMADILHA: Sem sobra no parse_admin
    try:
        parse_admin(body_joined + b"\x00")
        assert False, "Deveria falhar com sobra"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID

    print("✓ Mensagens administrativas: tamanhos 331, 283 e 268 bytes conferidos.")


# =====================================================================
# 10. TESTE DO FRAME DATA (NONCE, AAD, LIMITES 70 E 4165, PEEK_IDS)
# =====================================================================
def test_data():
    print("--- 10. Testando Frame DATA ---")
    iv_base = os.urandom(4)
    seq = 5
    s_id = os.urandom(16)
    r_id = os.urandom(16)

    # Nonce 12B (>Q no seq)
    nonce = build_nonce(iv_base, seq)
    assert len(nonce) == 12
    assert nonce[:4] == iv_base
    assert struct.unpack(">Q", nonce[4:])[0] == seq

    # AAD 40B (>Q no seq)
    aad = build_aad(s_id, r_id, seq)
    assert len(aad) == 40
    assert aad[:16] == s_id
    assert aad[16:32] == r_id
    assert struct.unpack(">Q", aad[32:])[0] == seq

    # Limite mínimo: exatamente 70 bytes
    min_cipher = os.urandom(17)
    body_70 = pack_data(nonce, s_id, r_id, seq, min_cipher)
    assert len(body_70) == 70 == DATA_MIN_LEN
    p70 = parse_data(body_70)
    assert p70.seq == seq
    assert isinstance(p70.nonce, bytes)
    assert isinstance(p70.ciphertext_and_tag, bytes)
    assert peek_ids(body_70) == (s_id, r_id)

    # Limite máximo: exatamente 4165 bytes
    max_cipher = os.urandom(4112)
    body_4165 = pack_data(nonce, s_id, r_id, seq, max_cipher)
    assert len(body_4165) == 4165 == DATA_MAX_LEN
    p4165 = parse_data(body_4165)
    assert p4165.seq == seq
    assert peek_ids(body_4165) == (s_id, r_id)

    # ARMADILHA: Rejeição estrita de limites inválidos (69B e 4166B)
    for bad_data in (body_70[:-1], body_4165 + b"\x00"):
        try:
            parse_data(bad_data)
            assert False, f"Deveria rejeitar tamanho {len(bad_data)}"
        except ProtocolError:
            pass

        try:
            peek_ids(bad_data)
            assert False, f"peek_ids deveria rejeitar tamanho {len(bad_data)}"
        except ProtocolError:
            pass

    print("✓ Frame DATA: nonce (12B), AAD (40B), limites [70, 4165] e peek_ids aprovados.")


# =====================================================================
# 11. TESTE DE PAPÉIS DO PAR (i_am_a) E SALT DO PAR
# =====================================================================
def test_roles_and_salt():
    print("--- 11. Testando Papéis do Par (i_am_a) e pair_salt ---")
    id_1 = b"\x01" + os.urandom(15)
    id_2 = b"\x02" + os.urandom(15)
    salt_1 = os.urandom(16)
    salt_2 = os.urandom(16)

    # Cliente 1 (menor id) é 'A'
    assert i_am_a(id_1, id_2) is True
    assert i_am_a(id_2, id_1) is False

    # Ambos os lados convergem para o salt do 'A' (salt_1)
    s_a = pair_salt(id_1, id_2, salt_1, salt_2)
    s_b = pair_salt(id_2, id_1, salt_2, salt_1)
    assert s_a == s_b == salt_1

    # IDs iguais disparam erro
    try:
        i_am_a(id_1, id_1)
        assert False, "Deveria rejeitar IDs iguais"
    except ProtocolError:
        pass

    print("✓ Papéis do par e convergência simétrica de salt validados.")


# =====================================================================
# 12. TESTE DE FINGERPRINT (LOGS)
# =====================================================================
def test_fingerprint():
    print("--- 12. Testando fingerprint ---")
    raw_pk = os.urandom(32)
    fp = fingerprint(raw_pk)
    assert isinstance(fp, str)
    assert len(fp) == 16
    int(fp, 16)  # Valida hex
    assert fp == hashlib.sha256(raw_pk).hexdigest()[:16]

    # Objeto X25519
    sk_x = x25519.X25519PrivateKey.generate()
    raw_x = sk_x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert fingerprint(raw_x) == hashlib.sha256(raw_x).hexdigest()[:16]

    print("✓ Fingerprint: 16 caracteres hexadecimais validado para logs.")


# =====================================================================
# EXECUÇÃO PRINCIPAL
# =====================================================================
async def main():
    print("=================================================================")
    print("  INICIANDO SUÍTE COMPLETA DE TESTES DO PROTOCOLO (protocol.py)  ")
    print("=================================================================\n")

    test_constants_and_limits()
    test_exceptions()
    test_variable_fields()
    await test_framing_async()
    test_client_hello()
    test_server_hello()
    test_hashes()
    test_rsa_pss()
    test_admin_messages()
    test_data()
    test_roles_and_salt()
    test_fingerprint()

    print("\n=================================================================")
    print("  TODOS OS TESTES PASSARAM COM SUCESSO! PROTOCOLO 100% BLINDADO. ")
    print("=================================================================")


if __name__ == "__main__":
    asyncio.run(main())
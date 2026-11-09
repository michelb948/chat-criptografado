# PROTOCOLO

Tudo big-endian. O código está em `protocol.py` e não deve ser alterado sem avisar o outro.

## FRAME

`[4B tamanho][1B tipo][campos]`. Tamanho `0` ou maior que `8192` é erro e fecha a conexão. Campo variável é `[2B tamanho][bytes]`. O corpo deve ser consumido exatamente, sem sobra.

## TIPOS

| Código | Tipo | Quem envia |
|---|---|---|
| 01 | `CLIENT_HELLO` | cliente |
| 02 | `SERVER_HELLO` | servidor |
| 03 | `DATA` | cliente (servidor só repassa) |
| 04 | `PEER_JOINED` | servidor |
| 05 | `PEER_LEFT` | servidor |
| 06 | `ERROR` | servidor |

Códigos de `ERROR`:

| Código | Motivo |
|---|---|
| 01 | framing inválido |
| 02 | frame grande demais |
| 03 | tipo desconhecido |
| 04 | destinatário offline |

## CONSTANTES

| Nome | Valor |
|---|---|
| `MAX_FRAME` | 8192 |
| `client_id`, `sender`, `recipient` | 16 bytes |
| `pk_C` (X25519 raw) | 32 bytes |
| `salt_srv` | 16 bytes |
| `nonce` | 12 bytes (`IV_base` 4 + `seq_no` 8) |
| chave AES-128 | 16 bytes |
| tag GCM | 16 bytes |
| plaintext máximo | 4096 bytes |
| salt interno do RSA-PSS | 32 bytes (não é o `salt_srv`) |

## FORMATOS

```text
CLIENT_HELLO: [01][client_id 16][pk_C 32]
SERVER_HELLO: [02][salt_srv 16][len][pk_S][len][server.crt][len][assinatura]
PEER_JOINED:  [04][client_id 16][pk_C 32][salt_do_peer 16][seq 8][len][assinatura]
PEER_LEFT:    [05][client_id 16][seq 8][len][assinatura]
ERROR:        [06][código 1][seq 8][len][assinatura]
DATA:         [03][nonce 12][sender 16][recipient 16][seq 8][ciphertext+tag 16]
```

`pk_S` é DER SubjectPublicKeyInfo e `server.crt` é DER. `DATA` tem de 70 a 4165 bytes .

## HANDSHAKE

```text
H = SHA256(pk_S_der || pk_C || client_id || salt_srv)
```

A assinatura é RSA-PSS sobre `H`, com MGF1-SHA256 e `salt_length=32`, tratando `H` como a mensagem (o PSS faz outro SHA-256 por dentro).

O cliente valida nesta ordem, e se algo falhar fecha a conexão sem derivar chaves: tamanhos batem, `server.crt` é igual ao pinado, `pk_S` é igual à chave do certificado, assinatura confere.

Ordem quando X entra: `CLIENT_HELLO`, checagem de `client_id` duplicado, `SERVER_HELLO`, um `PEER_JOINED` de cada cliente existente para X, um `PEER_JOINED` de X para cada existente.

## MENSAGENS ADMINISTRATIVAS

`H_adm = SHA256("ADMIN" || tipo || salt_destino || seq || payload)`, assinado igual ao handshake. O `salt_destino` é o salt do cliente que recebe e não viaja no frame.

O servidor mantém `seq_send` por sessão, começando em `0`, e não pode ter `await` entre pegar o `seq` e dar o `write`.

O cliente começa com `admin_seq_recv = -1` e valida nesta ordem: tamanho, `seq` maior que `admin_seq_recv`, assinatura, e só então atualiza o contador. Se falhar, fecha a conexão.

`PEER_JOINED` de ID já conhecido substitui a entrada e zera contadores. Do meu próprio ID, rejeita. `PEER_LEFT` apaga o peer.

## CHAVES E2E (cliente)

- `Z = X25519(sk_meu, pk_peer)`
- `A` é o menor `client_id` (comparação byte a byte). `salt_par` é o `salt_srv` do `A`.
- `PRK = HKDF-Extract(salt_par, Z)`, com HMAC-SHA256
- `Key_A2B = HKDF-Expand(PRK, "A2B", 16)` e `Key_B2A = HKDF-Expand(PRK, "B2A", 16)`
- Se eu sou `A`, `key_send` é `A2B` e `key_recv` é `B2A`. Se sou `B`, é o inverso.
- Estado inicial por peer: `seq_send=0`, `seq_recv=-1`, `IV_base_send=random(4)`, `IV_base_recv=None`.

## DATA

`nonce = IV_base_send || seq_no`. `AAD = sender || recipient || seq_no` (40 bytes). Cifra AES-128-GCM.

O receptor valida nesta ordem: tamanho entre 70 e 4165; `recipient` é eu; `sender` é conhecido; `nonce[4:12]` igual ao `seq_no`; `seq_no` maior que `seq_recv` e, se o IV já foi aprendido, `nonce[0:4]` igual a ele; decifra (tag inválida rejeita); só então atualiza `seq_recv` e, se era `None`, guarda `IV_base_recv = nonce[0:4]`.

O `IV_base_recv` é aprendido na primeira mensagem válida, porque o receptor não tem como sortear o IV do outro.

## SERVIDOR

- **Relay**: valida o tamanho, lê o `recipient` com `peek_ids()` e repassa sem alterar. Destino offline gera `ERROR 04` para o remetente, sem desconectar ninguém.
- **`client_id` duplicado**: fecha a conexão nova e mantém a antiga. Checar e registrar sem `await` no meio.
- `SO_KEEPALIVE` ligado. X só entra nas difusões depois de receber o `SERVER_HELLO`.
- Antes do `SERVER_HELLO` não existe `ERROR` assinado: se o `CLIENT_HELLO` for inválido, só fecha e loga.

## RECONEXÃO

Sempre handshake completo, X25519 novo e contadores zerados. O cliente aceita `--client-id`.

## LOGS

- **Pode**: conexão e desconexão, `client_id`, tamanhos, motivo de rejeição, `fingerprint(pk)`.
- **Não pode**: chaves privadas, `Z`, `salt`, `nonce`, conteúdo.

## FORA DO ENUNCIADO

`IV_base_recv` é aprendido, não sorteado. Mensagens administrativas são assinadas com RSA porque não há chave simétrica entre cliente e servidor. Clientes não são autenticados, e o E2E confia no servidor para entregar as chaves (mitigação: comparar fingerprints).

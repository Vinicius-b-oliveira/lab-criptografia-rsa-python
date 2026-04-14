# Laboratório de Criptografia Assimétrica RSA

Implementação do algoritmo RSA do zero, sem bibliotecas externas de criptografia, com fins puramente educacionais.

## O que é RSA?

RSA (Rivest-Shamir-Adleman) é um algoritmo de **criptografia assimétrica** — ou seja, usa duas chaves diferentes:

- **Chave pública**: qualquer pessoa pode ter. Serve para **criptografar** (trancar).
- **Chave privada**: somente o dono possui. Serve para **descriptografar** (destrancar).

A segurança do RSA se baseia em um fato matemático:

> **Multiplicar dois primos grandes é fácil. Fatorar o resultado de volta é praticamente impossível.**

---

## Como executar

```bash
# Dependências: nenhuma! Usa apenas a biblioteca padrão do Python 3.
# Não precisa de venv.

# Executa com 16 bits (padrão do lab)
python3 rsa_lab.py

# Executa com tamanho específico
python3 rsa_lab.py 16     # Chave de 16 bits (quebrável, didático)
python3 rsa_lab.py 32     # Chave de 32 bits (quebrável)
python3 rsa_lab.py 512    # Chave de 512 bits (formato PEM realista)
python3 rsa_lab.py 1024   # Chave de 1024 bits
```

---

## Etapas do laboratório

### 1. Fundamentos matemáticos

Antes de implementar o RSA, o script constrói as ferramentas matemáticas necessárias:

| Ferramenta                      | Para que serve                              | No RSA                                    |
| ------------------------------- | ------------------------------------------- | ----------------------------------------- |
| **MDC** (Algoritmo de Euclides) | Encontrar o maior divisor comum             | Verificar que `e` e `phi(n)` são coprimos |
| **MDC Estendido**               | Encontrar x,y tais que `ax + by = mdc(a,b)` | Base para calcular o inverso modular      |
| **Inverso Modular**             | Encontrar `d` tal que `e*d ≡ 1 (mod phi)`   | Calcular a chave privada `d`              |
| **Miller-Rabin**                | Testar se um número é primo                 | Garantir que `p` e `q` são primos         |

### 2. Geração de chaves

```
Passo 1:  Gera dois primos aleatórios ── p, q
Passo 2:  Calcula n = p * q            ── módulo (parte pública)
Passo 3:  Calcula phi(n) = (p-1)*(q-1) ── totiente de Euler (secreto!)
Passo 4:  Escolhe e = 65537            ── expoente público
Passo 5:  Calcula d = e^(-1) mod phi   ── expoente privado

Chave pública:  (e, n)    ── qualquer um pode ter
Chave privada:  (d, n)    ── somente o dono
```

**Por que `e = 65537`?**

- É primo
- Em binário: `10000000000000001` (só 2 bits ligados = exponenciação rápida)
- Grande o suficiente para resistir a certos ataques
- Padrão da indústria (OpenSSL, SSH, navegadores)

### 3. Criptografia e descriptografia

```
Criptografar:    ciphertext = message^e  mod n    (usa chave pública)
Descriptografar: message    = ciphertext^d  mod n (usa chave privada)
```

**Por que funciona?** Pelo Teorema de Euler:

```
(message^e)^d = message^(e*d) mod n

Como e*d ≡ 1 (mod phi(n)), temos e*d = 1 + k*phi(n)

message^(1 + k*phi(n)) = message * (message^phi(n))^k

Pelo Teorema de Euler: message^phi(n) ≡ 1 (mod n)

Portanto: message * 1^k = message ✓
```

### 4. Formato PEM (ASN.1/DER + Base64)

Quando você vê uma chave RSA em um arquivo SSH ou certificado SSL, ela se parece com isto:

```
-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJLA
HB8sUOJCXGCBh1aKd/LHIRbI3lMjPgDSsNKyfCb8
...
-----END RSA PRIVATE KEY-----
```

Isso **não é uma string aleatória**. É uma codificação em camadas:

```
Números inteiros (e, n, d, p, q...)
        │
        ▼
Estrutura ASN.1 ── define os campos e tipos
        │
        ▼
Bytes DER ── formato binário TLV (Tag-Length-Value)
        │           Tag:    "isto é um INTEGER"
        │           Length: "tem 64 bytes"
        │           Value:  os bytes do número
        ▼
Texto Base64 ── converte binário em caracteres imprimíveis
        │
        ▼
Bloco PEM ── adiciona cabeçalhos BEGIN/END
```

**Formato da chave pública (PKCS#1):**

```
SEQUENCE {
    modulus           INTEGER  -- n
    publicExponent    INTEGER  -- e
}
```

**Formato da chave privada (PKCS#1):**

```
SEQUENCE {
    version           INTEGER  -- 0
    modulus           INTEGER  -- n
    publicExponent    INTEGER  -- e
    privateExponent   INTEGER  -- d
    prime1            INTEGER  -- p
    prime2            INTEGER  -- q
    exponent1         INTEGER  -- d mod (p-1)   ── otimização CRT
    exponent2         INTEGER  -- d mod (q-1)   ── otimização CRT
    coefficient       INTEGER  -- q^(-1) mod p  ── otimização CRT
}
```

### 5. Quebrando a chave (ataque por fatoração)

O cenário do ataque:

```
1. Atacante tem a chave pública (e, n)     ── ela é pública!
2. Sabe que n = p * q                       ── precisa encontrar p e q
3. Fatora n para encontrar p e q            ── a parte "difícil"
4. Calcula phi(n) = (p-1) * (q-1)
5. Calcula d = mod_inverse(e, phi(n))
6. Pronto: tem a chave privada!
```

**Complexidade da fatoração por divisão por tentativa:**

| Tamanho da chave | Tentativas (~) | Tempo estimado |
| ---------------- | -------------- | -------------- |
| 16 bits          | ~256           | Instantâneo    |
| 32 bits          | ~65.000        | Instantâneo    |
| 64 bits          | ~4 bilhões     | Segundos       |
| 128 bits         | ~10^19         | Séculos        |
| 2048 bits        | ~10^308        | Impossível     |

---

## A chave é uma dupla de primos ou uma string aleatória?

**Matematicamente**, a chave é uma tupla de números inteiros:

- Pública: `(e, n)` — dois números
- Privada: `(d, n)` — dois números (mais p, q para otimização)

**No arquivo**, esses números são codificados em formato binário (DER) e convertidos para texto legível (Base64), resultando naquela "string aleatória" que você vê no SSH.

Ou seja: **a string aleatória é apenas a representação dos números, não os números em si.**

---

## SSH usa RSA?

**Sim, pode usar.** SSH é um **protocolo** que suporta vários algoritmos:

| Comando                 | Algoritmo                               |
| ----------------------- | --------------------------------------- |
| `ssh-keygen -t rsa`     | RSA                                     |
| `ssh-keygen -t ed25519` | Curvas Elípticas (EdDSA) — mais moderno |
| `ssh-keygen -t ecdsa`   | Curvas Elípticas (ECDSA)                |

O SSH usa RSA para **autenticação** (provar quem você é), não para criptografar o tráfego em si (para isso usa AES ou ChaCha20 via troca de chaves Diffie-Hellman).

---

## Estrutura do projeto

```
lab_rsa/
├── rsa_lab.py     # Script completo com todas as etapas documentadas
└── README.md      # Este arquivo
```

O script não usa nenhuma biblioteca externa de criptografia. Tudo é implementado do zero usando apenas:

- `math` — funções matemáticas básicas
- `secrets` — geração de números aleatórios criptograficamente seguros
- `base64` — codificação Base64
- `sys` — argumentos de linha de comando
- `time` — medição de tempo do ataque

---

## Glossário

| Termo                        | Definição                                                            |
| ---------------------------- | -------------------------------------------------------------------- |
| **RSA**                      | Algoritmo de criptografia assimétrica (Rivest-Shamir-Adleman)        |
| **Chave Pública (e, n)**     | Par de números que qualquer pessoa pode ter, usado para criptografar |
| **Chave Privada (d, n)**     | Par de números secreto do dono, usado para descriptografar           |
| **Módulo (n)**               | Produto dos dois primos: n = p \* q                                  |
| **Totiente de Euler phi(n)** | Quantidade de números coprimos com n: phi(n) = (p-1)(q-1)            |
| **Expoente Público (e)**     | Geralmente 65537, usado na criptografia                              |
| **Expoente Privado (d)**     | Inverso modular de e, usado na descriptografia                       |
| **MDC**                      | Máximo Divisor Comum                                                 |
| **Inverso Modular**          | Número d tal que e\*d ≡ 1 (mod phi(n))                               |
| **Miller-Rabin**             | Teste probabilístico de primalidade                                  |
| **ASN.1**                    | Padrão que define a estrutura dos dados de uma chave                 |
| **DER**                      | Codificação binária do ASN.1 (Tag-Length-Value)                      |
| **PEM**                      | Formato texto: Base64 do DER com cabeçalhos BEGIN/END                |
| **PKCS#1**                   | Padrão que define o formato específico de chaves RSA                 |
| **CRT**                      | Chinese Remainder Theorem — otimização para descriptografia          |
| **Fatoração**                | Decomposição de n em seus fatores primos p e q                       |

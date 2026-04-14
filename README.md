# Laboratório de Criptografia Assimétrica RSA

Implementação do algoritmo RSA do zero, sem bibliotecas externas de criptografia, com fins puramente educacionais.

## Sumário

- [O que é RSA?](#o-que-é-rsa)
- [Como executar](#como-executar)
- [Mapa do rsa_lab.py (funções, etapas e fluxos)](#mapa-do-rsa_labpy-funções-etapas-e-fluxos)
- [Legenda das saídas do terminal](#legenda-das-saídas-do-terminal)
- [Por que a chave privada tem 5 valores?](#por-que-a-chave-privada-tem-5-valores)
- [Etapas do laboratório](#etapas-do-laboratório)
- [A chave é uma dupla de primos ou uma string aleatória?](#a-chave-é-uma-dupla-de-primos-ou-uma-string-aleatória)
- [SSH usa RSA?](#ssh-usa-rsa)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Glossário](#glossário)

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
python3 rsa_lab.py 64     # Chave de 64 bits (a quebra pode levar minutos)
python3 rsa_lab.py 512    # Chave de 512 bits (formato PEM realista)
python3 rsa_lab.py 1024   # Chave de 1024 bits
```

---

## Mapa do rsa_lab.py (funções, etapas e fluxos)

Esta seção conecta diretamente o README ao arquivo [rsa_lab.py](rsa_lab.py), para facilitar estudo, revisão e apresentação.

### Fluxo principal (visão de chamada)

```text
main
  -> run_lab
          -> generate_keys
                  -> generate_prime
                          -> is_prime_miller_rabin
                  -> mod_inverse
                          -> extended_gcd
          -> demo_encryption
                  -> text_to_int
                  -> encrypt
                  -> decrypt
                  -> int_to_text
          -> demo_pem_format
                  -> public_key_to_pem
                          -> int_to_der
                                  -> encode_der_length
                          -> der_sequence
                  -> private_key_to_pem
                          -> mod_inverse
                          -> int_to_der
                                  -> encode_der_length
                          -> der_sequence
          -> demo_full_attack (somente para chaves pequenas)
                  -> encrypt
                  -> break_key
                          -> factorize
                          -> mod_inverse
                  -> decrypt
                  -> int_to_text
```

### Mapa de funções por responsabilidade

| Função                  | Papel no código                              | Etapa do lab                        |
| ----------------------- | -------------------------------------------- | ----------------------------------- |
| `gcd`                   | Calcula máximo divisor comum                 | Base matemática                     |
| `extended_gcd`          | Resolve combinação linear de Bézout          | Base matemática                     |
| `mod_inverse`           | Calcula inverso modular                      | Base matemática / Geração de chaves |
| `is_prime_miller_rabin` | Testa primalidade dos candidatos             | Base matemática                     |
| `generate_prime`        | Gera primos aleatórios de N bits             | Geração de chaves                   |
| `generate_keys`         | Gera `(e, n)` e `(d, n, p, q, e)`            | Etapa 1                             |
| `encrypt`               | Executa `message^e mod n`                    | Etapa 2                             |
| `decrypt`               | Executa `ciphertext^d mod n`                 | Etapa 2                             |
| `text_to_int`           | Converte texto para inteiro                  | Etapa 2                             |
| `int_to_text`           | Converte inteiro para texto                  | Etapa 2                             |
| `demo_encryption`       | Demonstra ciclo completo de cifra/decifra    | Etapa 2                             |
| `encode_der_length`     | Codifica campo Length no DER                 | Etapa 3                             |
| `int_to_der`            | Codifica INTEGER em DER                      | Etapa 3                             |
| `der_sequence`          | Empacota conteúdo como SEQUENCE DER          | Etapa 3                             |
| `private_key_to_pem`    | Monta chave privada PEM (PKCS#1)             | Etapa 3                             |
| `public_key_to_pem`     | Monta chave pública PEM (PKCS#1)             | Etapa 3                             |
| `demo_pem_format`       | Mostra resumo da exportação PEM              | Etapa 3                             |
| `factorize`             | Fatoração por divisão por tentativa          | Etapa 4                             |
| `break_key`             | Reconstrói chave privada a partir da pública | Etapa 4                             |
| `demo_full_attack`      | Simula interceptação + quebra + leitura      | Etapa 4                             |
| `run_lab`               | Orquestra as etapas didáticas                | Orquestração                        |
| `main`                  | Processa argumentos e inicia o fluxo         | Entrada do programa                 |

### Fluxos por etapa

**Etapa 1 (Geração de chaves)**

1. `run_lab` chama `generate_keys`.
2. `generate_keys` chama `generate_prime` duas vezes para `p` e `q`.
3. `generate_prime` usa `is_prime_miller_rabin` para validar candidatos.
4. O código calcula `n`, `phi(n)`, escolhe `e` e calcula `d` via `mod_inverse`.

**Etapa 2 (Criptografia/Descriptografia)**

1. `demo_encryption` converte mensagem com `text_to_int`.
2. Chama `encrypt` com chave pública.
3. Chama `decrypt` com chave privada.
4. Reconverte com `int_to_text` e compara resultado.

**Etapa 3 (PEM/DER)**

1. `demo_pem_format` chama `public_key_to_pem` e `private_key_to_pem`.
2. Ambas usam `int_to_der` e `der_sequence`.
3. `int_to_der` usa `encode_der_length`.
4. Saída final é Base64 com cabeçalhos PEM.

**Etapa 4 (Ataque por fatoração)**

1. Em chaves pequenas, `run_lab` chama `demo_full_attack`.
2. `demo_full_attack` intercepta cifrado e chama `break_key`.
3. `break_key` usa `factorize` para achar `p` e `q`.
4. Calcula `d` com `mod_inverse` e descriptografa a mensagem.

### Regra de execução para tamanhos maiores

- O ataque completo só roda automaticamente quando `prime_bits <= 32` (ex.: chave de até ~64 bits).
- Para tamanhos maiores, o script mostra estimativa de tempo da fatoração por tentativa e pula a execução para evitar travar o terminal.

---

## Legenda das saídas do terminal

Esta seção explica, campo por campo, o que aparece ao rodar `python3 rsa_lab.py <bits>`.

### Bloco inicial

- `LABORATORIO RSA - X bits`: tamanho aproximado da chave final (`n`).

### [ETAPA 1] Gerando chaves RSA

- `n (modulo)`: produto `p * q`; valor usado nas chaves pública e privada.
- `tamanho de n`: quantidade real de bits de `n`.
- `e (publico)`: expoente público (normalmente `65537`).
- `d (privado)`: expoente privado (inverso modular de `e` em `phi(n)`).
- `chave publica tupla`: representação direta `(e, n)`.
- `chave privada tupla`: representação didática completa `(d, n, p, q, e)`.
- `p e q`: mostrado apenas para tamanhos muito pequenos.

### [ETAPA 2] Criptografia e descriptografia

- `mensagem`: texto usado na demonstração.
- `inteiro`: mensagem convertida para inteiro (UTF-8 big-endian).
- `cifrado`: resultado de `message^e mod n`.
- `recuperado`: resultado após `ciphertext^d mod n` convertido de volta para texto.
- `status`: validação de igualdade entre original e recuperado.

### [ETAPA 3] Exportacao PEM

- `chave publica` e `chave privada` em linhas: tamanho textual do bloco PEM.
- `cabecalho publica/privada`: tipo de bloco PEM (`BEGIN ...`).
- `chave publica PEM` e `chave privada PEM`: conteúdo completo serializado.

### [ETAPA 4] Ataque por fatoracao

- `alvo n`: módulo público que o atacante tenta fatorar.
- `fatores encontrados`: `p` e `q` recuperados por fatoração.
- `tentativas`: quantidade de divisores testados.
- `tempo`: duração da fatoração por tentativa.
- `d recuperado`: expoente privado reconstruído a partir da chave pública.
- `chave privada recup`: tupla recuperada no ataque.
- `mensagem interceptada`: texto cifrado capturado pelo atacante.
- `mensagem recuperada`: texto após ataque + descriptografia.
- `status ataque`: confirma se `d` recuperado bate com o original.

---

## Por que a chave privada tem 5 valores?

No laboratório, a chave privada é exibida como:

```text
(d, n, p, q, e)
```

Isso é uma escolha didática e de implementação, não um requisito mínimo da descriptografia.

### O que cada valor representa

1. `d`: expoente privado (essencial para descriptografar).
2. `n`: módulo RSA (essencial para descriptografar).
3. `p`: primeiro primo usado para gerar `n`.
4. `q`: segundo primo usado para gerar `n`.
5. `e`: expoente público, mantido por conveniência e consistência do fluxo.

### O mínimo matemático vs o formato didático

- Mínimo para descriptografar RSA clássico: `(d, n)`.
- Formato usado no lab: `(d, n, p, q, e)`.

### Por que manter `p`, `q` e `e` no lab?

- Facilita montar a chave privada em PEM/PKCS#1 com todos os campos relevantes.
- Permite inspeção didática completa da construção da chave.
- Ajuda em otimizações e validações (como componentes CRT).

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

#### Detalhamento dos algoritmos da base

**1) MDC (Algoritmo de Euclides)**

O MDC é calculado por substituições sucessivas:

```text
gcd(48, 18)
-> gcd(18, 12)
-> gcd(12, 6)
-> gcd(6, 0)
-> 6
```

Regra usada a cada passo: `(a, b) -> (b, a % b)`.

No RSA, isso valida que `gcd(e, phi(n)) = 1`. Sem essa condição, o inverso modular de `e` não existe.

**2) Euclides Estendido**

Além do MDC, ele encontra `x` e `y` tais que:

```text
a*x + b*y = gcd(a, b)
```

Exemplo resumido para `a=35`, `b=15`:

```text
extended_gcd(35, 15)
        -> extended_gcd(15, 5)
                -> extended_gcd(5, 0) = (5, 1, 0)
```

Voltando da recursão, reconstruímos os coeficientes e obtemos a combinação linear que permite calcular o inverso modular.

**3) Inverso modular (`mod_inverse`)**

Queremos `d` tal que:

```text
(e * d) % phi = 1
```

Exemplo:

```text
e = 3, phi = 20
3 * 7 = 21
21 % 20 = 1
=> d = 7
```

Esse `d` é o expoente privado do RSA. Sem ele, não existe descriptografia RSA clássica.

**4) Miller-Rabin (primalidade probabilística)**

Para um `n` ímpar:

1. Escrevemos `n-1 = 2^r * d`, com `d` ímpar.
2. Escolhemos uma base aleatória `a` em `[2, n-2]`.
3. Calculamos `x = a^d mod n`.
4. Se `x = 1` ou `x = n-1`, a rodada passa.
5. Senão, elevamos `x` ao quadrado até `r-1` vezes.
6. Se nunca surgir `n-1`, `n` é composto.

Cada rodada reduz muito a chance de falso positivo. Com 20 rodadas, a probabilidade de aceitar composto fica desprezível para o uso didático.

**5) Geração de primos (`generate_prime`)**

Estratégia usada no lab:

1. Gera candidato aleatório com `bits` bits.
2. Força bit mais significativo para garantir tamanho.
3. Força bit menos significativo para garantir número ímpar.
4. Testa primalidade com Miller-Rabin.
5. Repete até achar primo.

Isso mantém o código simples, com geração suficientemente boa para o propósito da disciplina.

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

#### Conversão texto <-> inteiro

Como RSA opera sobre inteiros, o lab converte texto em bytes UTF-8 e depois em inteiro big-endian:

```text
"Hi" -> [72, 105] -> 0x4869 -> 18537
```

Na volta, faz o processo inverso: inteiro -> bytes -> string UTF-8.

#### Limitação importante

O valor numérico da mensagem deve ser menor que `n`. Quando não cabe, há truncamento didático no exemplo.

No mundo real, usa-se criptografia híbrida:

1. RSA cifra uma chave simétrica curta.
2. AES/ChaCha20 cifra os dados grandes.

Isso evita limitações de tamanho e melhora desempenho.

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

#### DER na prática (TLV)

O DER usa estrutura Tag-Length-Value:

- `Tag`: tipo ASN.1 (`0x02` para INTEGER, `0x30` para SEQUENCE)
- `Length`: tamanho do conteúdo
- `Value`: bytes do campo

**Codificação de `Length`**

- Curta: se `< 128`, um byte só (`0x05` para tamanho 5)
- Longa: se `>= 128`, primeiro byte indica quantos bytes de tamanho vêm depois

Exemplos:

```text
200  -> 0x81 0xC8
1000 -> 0x82 0x03 0xE8
```

**Inteiros positivos em DER**

Como INTEGER ASN.1 é assinado, se o bit mais significativo vier `1`, adiciona-se prefixo `0x00` para garantir interpretação positiva.

Exemplo: `128` (`0x80`) vira `0x00 0x80`.

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

| Tamanho da chave | Tentativas (~) | Tempo estimado                   |
| ---------------- | -------------- | -------------------------------- |
| 16 bits          | ~256           | Instantâneo                      |
| 32 bits          | ~65.000        | Instantâneo                      |
| 64 bits          | ~4 bilhões     | Segundos ou minutos (ex.: ~120s) |
| 128 bits         | ~10^19         | Séculos                          |
| 2048 bits        | ~10^308        | Impossível                       |

Observação: o tempo real depende de CPU, linguagem, implementação e carga da máquina no momento do teste.

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
├── rsa_lab.py     # Script com lógica e execução das etapas
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

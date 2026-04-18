# Laboratório de Criptografia Assimétrica RSA

Implementação do algoritmo RSA do zero, sem bibliotecas externas de criptografia, com fins puramente educacionais.

## Sumário

- [O que é RSA?](#o-que-é-rsa)
- [Como executar](#como-executar)
- [CLI interativa](#cli-interativa)
- [Execução individual por etapa (CLIs)](#execução-individual-por-etapa-clis)
- [Mapa do código (funções, etapas e fluxos)](#mapa-do-código-funções-etapas-e-fluxos)
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
# O lab e os CLIs usam apenas a biblioteca padrão do Python 3.
# A CLI interativa (rsa_cli.py) precisa de venv com simple-term-menu.

# Setup do venv (necessário apenas para rsa_cli.py)
python3 -m venv .venv
source .venv/bin/activate     # Linux/Mac
pip install -r requirements.txt

# Executa com 16 bits (padrão do lab)
python3 rsa_lab.py

# Executa com tamanho específico
python3 rsa_lab.py 16     # Chave de 16 bits (quebrável, didático)
python3 rsa_lab.py 32     # Chave de 32 bits (quebrável)
python3 rsa_lab.py 64     # Chave de 64 bits (a quebra pode levar minutos)
python3 rsa_lab.py 512    # Chave de 512 bits (formato PEM realista)
python3 rsa_lab.py 1024   # Chave de 1024 bits
```

## CLI interativa

Interface com menus de seleção (requer venv ativado):

```bash
source .venv/bin/activate
python3 rsa_cli.py
```

```text
========================================
  RSA Lab - CLI Interativa
========================================

  O que deseja fazer?
> Gerar chaves
  Encriptar mensagem
  Decriptar mensagem
  Quebrar chave (fatoracao)
  Quebrar chave (performance)
  Exibir PEM
  Status da sessao
  Sair
```

Use as setas (cima/baixo) para navegar e Enter para selecionar. As chaves geradas ficam em memória durante a sessão.

| Opção do menu               | Ação                                                                           |
| --------------------------- | ------------------------------------------------------------------------------ |
| Gerar chaves                | Escolhe tamanho (16-2048 bits) e gera par de chaves                            |
| Encriptar mensagem          | Pede texto e formato (didático ou raw Base64)                                  |
| Decriptar mensagem          | Decripta último cifrado da sessão ou entrada manual                            |
| Quebrar chave (fatoração)   | Tenta fatorar a chave pública (com aviso para chaves grandes)                  |
| Quebrar chave (performance) | Quebra a chave pública via Pollard Rho (mais rápido em chaves pequenas/médias) |
| Exibir PEM                  | Mostra chaves pública e privada em formato PEM                                 |
| Status da sessão            | Resumo da chave ativa e último cifrado                                         |
| Sair                        | Encerra a CLI                                                                  |

A CLI interativa depende de `simple-term-menu` (instalado via `requirements.txt`). Os demais scripts funcionam sem dependências externas.

---

## Execução individual por etapa (CLIs)

Além do fluxo completo em [rsa_lab.py](rsa_lab.py), também é possível executar etapas de forma separada:

```bash
# 1) Gerar chaves (tupla + PEM)
python3 rsa_keygen.py 64

# 1b) Gerar e salvar PEM em arquivo (diretorio local)
python3 rsa_keygen.py 64 --output file

# 1c) Gerar e mostrar no terminal + salvar em arquivo
python3 rsa_keygen.py 64 --output both

# 2) Criptografar com chave pública (p=61, q=53 → n=3233, e=17)
python3 rsa_encrypt.py '(17, 3233)' 'mensagem'

# 2b) Criptografar em formato realista (Base64 binário)
python3 rsa_encrypt.py --raw '(17, 3233)' 'mensagem longa'

# 3) Descriptografar com chave privada (d=2753 para o par acima)
python3 rsa_decrypt.py '(2753, 3233)' '987654321'

# 3b) Descriptografar a partir do formato raw
python3 rsa_decrypt.py --raw private.pem 'PKsir4p7TEL...'

# 4) Quebrar chave pública (didático)
python3 rsa_break.py '(17, 3233)'

# 4b) Quebrar chave pública (performance, Pollard Rho)
python3 brute_force.py '(17, 3233)'

# Também aceita PEM por arquivo
python3 rsa_encrypt.py public.pem 'mensagem'
python3 rsa_decrypt.py private.pem '987654321'
python3 rsa_break.py public.pem
python3 brute_force.py public.pem
```

Observação: os CLIs aceitam chave em tupla, PEM literal (texto) ou caminho para arquivo `.pem`.

Para o `rsa_encrypt.py` e `rsa_decrypt.py`:

- Sem flag: saída/entrada didática (inteiros separados por vírgula).
- `--raw`: saída/entrada em blocos binários de tamanho fixo concatenados e codificados em Base64. **Apenas cosmético** — o algoritmo por baixo continua sendo o RSA acadêmico do lab; só a representação visual muda para lembrar um payload real. Ver a seção "O modo `--raw` é só cosmético" mais abaixo.

Para o `rsa_keygen.py`:

- `--output terminal` (padrão): imprime PEM no terminal.
- `--output file`: salva PEM em arquivos na pasta `keys/` (ou em `--out-dir`).
- `--output both`: imprime no terminal e também salva em arquivo.

Arquivos da versão modular:

- [rsa_core.py](rsa_core.py): funções compartilhadas (matemática, RSA, PEM e fatoração).
- [rsa_keygen.py](rsa_keygen.py): geração de chaves.
- [rsa_encrypt.py](rsa_encrypt.py): criptografia.
- [rsa_decrypt.py](rsa_decrypt.py): descriptografia.
- [rsa_break.py](rsa_break.py): ataque por fatoração.
- [brute_force.py](brute_force.py): ataque por fatoração focado em performance (Pollard Rho).

---

## Mapa do código (funções, etapas e fluxos)

Esta seção conecta diretamente o README ao código-fonte, para facilitar estudo. As funções de negócio ficam em [rsa_core.py](rsa_core.py), e a orquestração didática em [rsa_lab.py](rsa_lab.py).

### Fluxo principal (visão de chamada)

```text
main
  -> run_lab
          -> demo_generate_keys
                  -> generate_keys
                          -> generate_prime
                                  -> is_prime_miller_rabin
                          -> mod_inverse
                                  -> extended_gcd
          -> demo_encryption
                  -> text_to_int / encrypt / decrypt / int_to_text  (1 bloco)
                  -> encrypt_text / decrypt_text                    (N blocos)
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

| Função                    | Arquivo       | Papel no código                              | Etapa / Categoria                   |
| ------------------------- | ------------- | -------------------------------------------- | ----------------------------------- |
| `gcd`                     | `rsa_core.py` | Calcula máximo divisor comum                 | Base matemática                     |
| `extended_gcd`            | `rsa_core.py` | Resolve combinação linear de Bézout          | Base matemática                     |
| `mod_inverse`             | `rsa_core.py` | Calcula inverso modular                      | Base matemática / Geração de chaves |
| `is_prime_miller_rabin`   | `rsa_core.py` | Testa primalidade dos candidatos             | Base matemática                     |
| `generate_prime`          | `rsa_core.py` | Gera primos aleatórios de N bits             | Geração de chaves                   |
| `generate_keys`           | `rsa_core.py` | Gera `(e, n)` e `(d, n, p, q, e)`            | Etapa 1                             |
| `encrypt`                 | `rsa_core.py` | Executa `message^e mod n`                    | Etapa 2 (primitiva)                 |
| `decrypt`                 | `rsa_core.py` | Executa `ciphertext^d mod n`                 | Etapa 2 (primitiva)                 |
| `text_to_int`             | `rsa_core.py` | Converte texto para inteiro                  | Etapa 2                             |
| `int_to_text`             | `rsa_core.py` | Converte inteiro para texto                  | Etapa 2                             |
| `block_size`              | `rsa_core.py` | Calcula bytes por bloco para uma chave       | Etapa 2 (blocos)                    |
| `encrypt_text`            | `rsa_core.py` | Divide texto em blocos e encripta cada um    | Etapa 2 (blocos)                    |
| `decrypt_text`            | `rsa_core.py` | Decifra blocos e remonta o texto             | Etapa 2 (blocos)                    |
| `cipher_block_size`       | `rsa_core.py` | Tamanho fixo do bloco cifrado (bytes de `n`) | Etapa 2 (serialização raw)          |
| `blocks_to_raw`           | `rsa_core.py` | Serializa blocos cifrados em Base64 binário  | Etapa 2 (serialização raw)          |
| `raw_to_blocks`           | `rsa_core.py` | Deserializa Base64 de volta para blocos      | Etapa 2 (serialização raw)          |
| `encode_der_length`       | `rsa_core.py` | Codifica campo Length no DER                 | Etapa 3 (escrita PEM)               |
| `int_to_der`              | `rsa_core.py` | Codifica INTEGER em DER                      | Etapa 3 (escrita PEM)               |
| `der_sequence`            | `rsa_core.py` | Empacota conteúdo como SEQUENCE DER          | Etapa 3 (escrita PEM)               |
| `public_key_to_pem`       | `rsa_core.py` | Monta chave pública PEM (PKCS#1)             | Etapa 3 (escrita PEM)               |
| `private_key_to_pem`      | `rsa_core.py` | Monta chave privada PEM (PKCS#1)             | Etapa 3 (escrita PEM)               |
| `_read_der_length`        | `rsa_core.py` | Lê campo Length de um bloco DER              | Etapa 3 (leitura PEM)               |
| `_read_der_integer`       | `rsa_core.py` | Lê campo INTEGER de um bloco DER             | Etapa 3 (leitura PEM)               |
| `_read_der_sequence`      | `rsa_core.py` | Lê SEQUENCE inteira e extrai INTEGERs        | Etapa 3 (leitura PEM)               |
| `_extract_pem_content`    | `rsa_core.py` | Extrai bytes Base64 de um bloco PEM          | Etapa 3 (leitura PEM)               |
| `parse_public_key_pem`    | `rsa_core.py` | Deserializa chave pública de PEM             | Etapa 3 (leitura PEM)               |
| `parse_private_key_pem`   | `rsa_core.py` | Deserializa chave privada de PEM             | Etapa 3 (leitura PEM)               |
| `factorize`               | `rsa_core.py` | Fatoração por divisão por tentativa          | Etapa 4                             |
| `break_key`               | `rsa_core.py` | Reconstrói chave privada a partir da pública | Etapa 4                             |
| `parse_key_tuple`         | `rsa_core.py` | Converte texto em tupla Python               | Parsing de entrada (CLIs)           |
| `parse_public_key`        | `rsa_core.py` | Valida tupla como chave pública `(e, n)`     | Parsing de entrada (CLIs)           |
| `parse_private_key`       | `rsa_core.py` | Valida tupla como chave privada              | Parsing de entrada (CLIs)           |
| `resolve_key_input`       | `rsa_core.py` | Decide se input é arquivo ou texto literal   | Parsing de entrada (CLIs)           |
| `parse_public_key_input`  | `rsa_core.py` | Ponto de entrada: parsing de chave pública   | Parsing de entrada (CLIs)           |
| `parse_private_key_input` | `rsa_core.py` | Ponto de entrada: parsing de chave privada   | Parsing de entrada (CLIs)           |
| `demo_generate_keys`      | `rsa_lab.py`  | Exibe geração de chaves                      | Etapa 1 (orquestração)              |
| `demo_encryption`         | `rsa_lab.py`  | Demonstra ciclo completo de cifra/decifra    | Etapa 2 (orquestração)              |
| `demo_pem_format`         | `rsa_lab.py`  | Mostra resumo da exportação PEM              | Etapa 3 (orquestração)              |
| `demo_full_attack`        | `rsa_lab.py`  | Simula interceptação + quebra + leitura      | Etapa 4 (orquestração)              |
| `run_lab`                 | `rsa_lab.py`  | Orquestra as etapas didáticas                | Orquestração                        |
| `main`                    | `rsa_lab.py`  | Processa argumentos e inicia o fluxo         | Entrada do programa                 |

### Fluxos por etapa

**Etapa 1 (Geração de chaves)**

1. `run_lab` chama `generate_keys`.
2. `generate_keys` chama `generate_prime` duas vezes para `p` e `q`.
3. `generate_prime` usa `is_prime_miller_rabin` para validar candidatos.
4. O código calcula `n`, `phi(n)`, escolhe `e` e calcula `d` via `mod_inverse`.

**Etapa 2 (Criptografia/Descriptografia)**

Etapa 2a (1 bloco — criptografia clássica):

1. `demo_encryption` converte mensagem curta com `text_to_int`.
2. Chama `encrypt` com chave pública.
3. Chama `decrypt` com chave privada.
4. Reconverte com `int_to_text` e compara resultado.

Etapa 2b (N blocos — mensagem maior que `n`):

1. `demo_encryption` chama `encrypt_text` com mensagem longa.
2. `encrypt_text` divide o texto em blocos de `block_size` bytes.
3. Cada bloco é convertido para inteiro e encriptado individualmente.
4. `decrypt_text` decifra cada bloco e concatena os bytes de volta.
5. Compara o texto recuperado com o original.

**Etapa 3 (PEM/DER)**

Escrita (tupla → PEM):

1. `demo_pem_format` chama `public_key_to_pem` e `private_key_to_pem`.
2. Ambas usam `int_to_der` e `der_sequence`.
3. `int_to_der` usa `encode_der_length`.
4. Saída final é Base64 com cabeçalhos PEM.

Leitura (PEM → tupla), usada pelos CLIs:

1. `parse_public_key_input` / `parse_private_key_input` detecta se input é PEM ou tupla.
2. Se PEM: `_extract_pem_content` extrai o Base64 e decodifica para bytes DER.
3. `_read_der_sequence` percorre os blocos TLV extraindo cada INTEGER.
4. `parse_public_key_pem` / `parse_private_key_pem` monta a tupla final.

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

### [ETAPA 2a] Criptografia clássica (1 bloco)

- `mensagem`: texto curto usado na demonstração (cabe em 1 bloco).
- `inteiro`: mensagem convertida para inteiro (UTF-8 big-endian).
- `cifrado`: resultado de `message^e mod n`.
- `recuperado`: resultado após `ciphertext^d mod n` convertido de volta para texto.
- `status`: validação de igualdade entre original e recuperado.

### [ETAPA 2b] Criptografia por blocos (mensagem maior que n)

- `mensagem`: texto longo que não cabe em um único bloco.
- `bytes da mensagem`: tamanho total da mensagem em bytes UTF-8.
- `tamanho do bloco`: quantos bytes cabem em cada bloco (calculado a partir de `n`).
- `blocos cifrados`: quantidade de blocos gerados.
- `bloco N`: valor cifrado de cada bloco individual.
- `recuperado`: texto remontado após decifrar todos os blocos.
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

#### Encriptação por blocos (mensagens maiores que `n`)

O RSA só encripta um inteiro menor que `n` por vez. Para mensagens maiores, o lab divide o texto em **blocos**:

```text
"Mensagem grande demais"        (22 bytes)
        │
        ▼
Texto em bytes UTF-8            [4d 65 6e 73 61 67 65 6d ...]
        │
        ▼
Divide em blocos de B bytes     B = (bits de n - 1) / 8
        │                       (garante que cada bloco < n)
        ▼
Bloco 1: [4d 65 6e 73 61 67 65]  → inteiro → encrypt → cifrado₁
Bloco 2: [6d 20 67 72 61 6e 64]  → inteiro → encrypt → cifrado₂
Bloco 3: [65 20 64 65 6d 61 69]  → inteiro → encrypt → cifrado₃
Bloco 4: [73]                     → inteiro → encrypt → cifrado₄
        │
        ▼
Saída: cifrado₁, cifrado₂, cifrado₃, cifrado₄
```

Na descriptografia, cada bloco cifrado é decifrado individualmente e os bytes são concatenados de volta.

| Função         | Papel                                     |
| -------------- | ----------------------------------------- |
| `block_size`   | Calcula quantos bytes cabem em um bloco   |
| `encrypt_text` | Divide texto em blocos e encripta cada um |
| `decrypt_text` | Decifra cada bloco e remonta o texto      |

As funções primitivas `encrypt` e `decrypt` continuam operando sobre um único inteiro — as funções de bloco usam elas internamente.

#### Modelo acadêmico vs. RSA real (importante)

A cifragem por blocos que o lab implementa é **didática**, não o que o mundo real usa. Entender a diferença é fundamental.

**O que o lab faz:**

1. Divide o texto em blocos de `(bits de n − 1) / 8` bytes.
2. Cada bloco vira um inteiro e é passado direto para `m^e mod n`.
3. Sem padding, sem aleatoriedade, sem autenticação.
4. Equivale ao modo ECB de cifras simétricas aplicado a RSA — mesmo texto sempre gera o mesmo cifrado.

**Por que isso é inseguro na vida real:**

| Problema                     | Consequência                                                               |
| ---------------------------- | -------------------------------------------------------------------------- |
| **Determinismo**             | Mesma mensagem → mesmo cifrado. Dá pra "catalogar" cifrados conhecidos.    |
| **Mensagens pequenas**       | Se `m < n^(1/e)`, basta tirar a raiz e-ésima — sem inverter RSA.           |
| **Maleabilidade**            | `c₁ * c₂ mod n` decripta para `m₁ * m₂`. Atacante manipula sem a chave.    |
| **Blocos independentes**     | Dá pra reordenar, remover ou reusar blocos — sem integridade.              |
| **Sem autenticação**         | Qualquer um com a chave pública pode forjar cifrados.                      |

**Como RSA é usado de verdade:**

1. **Padding OAEP (RSAES-OAEP, PKCS#1 v2.x)**: antes de cifrar, a mensagem é embaralhada com uma função aleatória + hash. Isso mata o determinismo e fecha os ataques acima. Cada cifragem é única mesmo pro mesmo texto.
2. **Criptografia híbrida (o caso mais comum)**: RSA quase nunca cifra os dados. O padrão real é:
   ```
   Alice quer mandar um arquivo pra Bob:
     1. Alice gera uma chave AES aleatória (256 bits)
     2. Alice cifra o arquivo com AES (rápido, cifra gigabytes)
     3. Alice cifra só a chave AES com RSA-OAEP da Bob (1 operação, 256 bits)
     4. Envia: [AES(arquivo) || RSA(chave_AES)]
   ```
   RSA cifra apenas uma chave pequena; AES faz o trabalho pesado.
3. **TLS moderno (HTTPS)**: nem usa mais RSA pra cifrar. Usa **ECDHE** (Diffie-Hellman efêmero em curvas elípticas) pra trocar chaves, e RSA só como **assinatura** do certificado — provando a identidade do servidor, não protegendo os dados.

**Onde nosso lab "trapaceia":** cifra o texto inteiro com RSA direto, bloco por bloco, sem padding. Funciona para demonstrar a matemática, mas **nenhum sistema real faz isso**.

#### O modo `--raw` é só cosmético

Os CLIs `rsa_encrypt.py` e `rsa_decrypt.py` aceitam a flag `--raw`. É tentador achar que ela "deixa realista", mas **não muda a criptografia** — só muda a representação do cifrado na tela.

| Modo           | O que sai no terminal                  | Algoritmo por baixo          |
| -------------- | -------------------------------------- | ---------------------------- |
| Padrão         | Lista de inteiros separados por vírgula | Mesmo RSA acadêmico por blocos |
| `--raw`        | String Base64 que parece "lixo binário" | Mesmo RSA acadêmico por blocos |

O que `--raw` faz tecnicamente ([rsa_core.py:156-173](rsa_core.py#L156-L173)):

1. Cada bloco cifrado é serializado em bytes de **tamanho fixo** (`cipher_block_size`, igual em bytes ao `n`).
2. Os bytes de todos os blocos são concatenados.
3. O resultado é codificado em Base64.

É o mesmo empacotamento que TLS/SSH usam para cifrados reais — por isso **visualmente** o output lembra um payload real. Mas o conteúdo continua sendo o RSA acadêmico do lab, só embrulhado diferente. Serve para ilustrar "como dados criptografados *aparecem* em sistemas reais", não "como são gerados em sistemas reais".

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

#### Dois scripts de ataque: divisão por tentativa vs. Pollard Rho

O lab oferece **duas implementações** do ataque, com a mesma finalidade mas complexidades radicalmente diferentes:

| Aspecto         | [rsa_break.py](rsa_break.py)                       | [brute_force.py](brute_force.py)                       |
| --------------- | -------------------------------------------------- | ------------------------------------------------------ |
| Algoritmo       | Divisão por tentativa                              | Pollard Rho (ciclo de Floyd)                           |
| Complexidade    | **O(√n)**                                          | **O(n^(1/4))**                                         |
| Estratégia      | Testa todo ímpar entre √n e 3                      | Colisões pseudoaleatórias via `x = x² + c mod n`       |
| Finalidade      | Didática — a "ideia óbvia" do ataque               | Performance — usado na CLI interativa                  |
| Onde é chamado  | `rsa_break.py`, `rsa_lab.py` (etapa 4), `rsa_cli.py` (opção "fatoração") | `brute_force.py`, `rsa_cli.py` (opção "performance") |

**Por que Pollard Rho é tão mais rápido?**

Em vez de caçar o fator direto (√n iterações), ele explora o **paradoxo do aniversário**: gera uma sequência pseudoaleatória e aguarda uma colisão módulo `p`, que aparece em ~n^(1/4) passos. Quando a colisão acontece, `gcd(|x−y|, n)` delata o fator. Não é que o algoritmo "acha" `p` — ele esbarra numa coincidência que revela `p`.

**Impacto prático em single-thread:**

| Tamanho de n | Divisão por tentativa | Pollard Rho        |
| ------------ | --------------------- | ------------------ |
| 32 bits      | Instantâneo           | Instantâneo        |
| 64 bits      | ~minutos              | Milissegundos      |
| 96 bits      | Horas                 | ~1 segundo         |
| 128 bits     | Séculos               | Minutos            |
| 200 bits     | Inviável              | Começa a pesar     |

Ou seja: a barreira prática do lab sobe de ~64 bits para ~128–160 bits apenas trocando o algoritmo — sem paralelismo e sem dependência externa.

#### Até onde daria pra ir (escolhas que o lab não fez)

O projeto é propositalmente restrito à biblioteca padrão do Python. Se relaxássemos essa restrição, os próximos saltos seriam:

**Otimizações sem sair da stdlib** (poderiam ser feitas no próprio `brute_force.py`):

- **Brent** no lugar de Floyd: ~25% menos iterações no ciclo.
- **GCD em lote**: acumular o produto por ~100 passos antes de chamar `math.gcd` — o `gcd` é o custo dominante por iteração.
- **Pollard p−1** como pré-passo: se `p−1` for smooth (produto de primos pequenos), quebra em milissegundos.
- **Paralelismo com `multiprocessing`**: Rho paraleliza quase linearmente (cada worker com um `c` diferente). Limitar com `cpu_count() - 2` + `os.nice(10)` evita explodir o PC.

**Com libs externas** (fora do escopo do lab):

| Lib / Ferramenta             | Ganho                                                           |
| ---------------------------- | --------------------------------------------------------------- |
| `gmpy2`                      | Big int 5–10× mais rápido — acelera chaves E ataque             |
| `sympy.ntheory.factorint`    | ECM + Rho + Pollard p−1 combinados — 128 bits em segundos       |
| **ECM** (dedicado)           | Imbatível até ~60 dígitos — próximo salto algorítmico sobre Rho |
| **msieve / YAFU / CADO-NFS** | QS e GNFS — padrão industrial, único caminho para 512+ bits     |

**O que não muda:** 1024 bits segue inviável sem cluster; 2048 bits, sem computação quântica. A segurança prática do RSA não depende da escolha da stack de ataque — depende do tamanho da chave.

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
├── rsa_core.py         # Núcleo reutilizável (matemática, RSA, PEM, parsing, fatoração)
├── rsa_lab.py          # Orquestrador das 4 etapas didáticas
├── rsa_cli.py          # CLI interativa com menus de seleção (requer venv)
├── rsa_keygen.py       # CLI: geração de chaves
├── rsa_encrypt.py      # CLI: criptografia com chave pública
├── rsa_decrypt.py      # CLI: descriptografia com chave privada
├── rsa_break.py        # CLI: quebra didática por fatoração
├── brute_force.py      # CLI: quebra por performance (Pollard Rho)
├── requirements.txt    # Dependência da CLI interativa (simple-term-menu)
└── README.md           # Este arquivo
```

O núcleo criptográfico (`rsa_core.py`) e todos os CLIs individuais usam apenas a biblioteca padrão do Python 3. A CLI interativa (`rsa_cli.py`) é a única que depende de pacote externo (`simple-term-menu`, para menus com setinhas).

**Bibliotecas padrão usadas:**

- `math` — funções matemáticas básicas (`isqrt`)
- `secrets` — geração de números aleatórios criptograficamente seguros
- `base64` — codificação Base64
- `sys` — argumentos de linha de comando
- `time` — medição de tempo do ataque
- `ast` — parsing seguro de tuplas (`literal_eval`)
- `os` — verificação de caminhos de arquivo
- `argparse` — argumentos CLI do `rsa_keygen.py`, `rsa_encrypt.py` e `rsa_decrypt.py`
- `datetime` — timestamp para nomes de arquivos PEM
- `pathlib` — manipulação de caminhos multiplataforma

**Dependência externa (apenas `rsa_cli.py`):**

- `simple-term-menu` — menus interativos com navegação por setas no terminal

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

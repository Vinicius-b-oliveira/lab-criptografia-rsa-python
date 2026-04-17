# Guia de Apresentação — Laboratório RSA

Roteiro para o grupo preparar e apresentar o laboratório de criptografia assimétrica RSA.

---

## Visão geral do que o projeto faz

O projeto implementa o algoritmo RSA **do zero**, sem bibliotecas de criptografia. Ele cobre:

1. Fundamentos matemáticos (MDC, inverso modular, teste de primalidade)
2. Geração de chaves (pública e privada)
3. Criptografia e descriptografia (incluindo mensagens grandes, por blocos)
4. Serialização de chaves em formato PEM (o formato que SSH e certificados usam)
5. Ataque por fatoração (quebrando chaves pequenas para mostrar por que chaves grandes importam)

O objetivo didático é mostrar que **RSA é matemática pura** — não é mágica, não é uma caixa preta. Cada etapa pode ser acompanhada no terminal.

---

## Sugestão de slides

### Slide 1 — O que é criptografia assimétrica?

- Dois tipos de criptografia: **simétrica** (mesma chave) vs **assimétrica** (chaves diferentes)
- Assimétrica: uma chave tranca (pública), outra destranca (privada)
- Analogia: cadeado aberto (qualquer um tranca) vs chave do cadeado (só o dono abre)
- RSA é o algoritmo assimétrico mais conhecido — criado em 1977 por Rivest, Shamir e Adleman

### Slide 2 — A ideia central do RSA

- Baseado em um fato matemático: **multiplicar dois primos é fácil, fatorar o produto é quase impossível**
- Exemplo rápido: 61 x 53 = 3233 (fácil). Dado 3233, ache os fatores (difícil se os números forem enormes)
- Isso é o que torna RSA seguro: a chave pública expõe o produto, mas sem os fatores ninguém calcula a chave privada

### Slide 3 — Geração de chaves (passo a passo)

```
1. Gera dois primos aleatórios      → p, q
2. Multiplica                        → n = p * q       (módulo)
3. Calcula totiente de Euler         → phi = (p-1)(q-1)
4. Escolhe expoente público          → e = 65537
5. Calcula expoente privado          → d = inverso de e mod phi

Chave pública:  (e, n)   — qualquer um pode ter
Chave privada:  (d, n)   — só o dono
```

- Mostrar que `e = 65537` é padrão da indústria (OpenSSL, SSH, navegadores)
- Explicar por que: é primo, tem só 2 bits ligados em binário (rápido de calcular)

### Slide 4 — Criptografia e descriptografia

```
Encriptar:    cifrado  = mensagem^e  mod n    (chave pública)
Decriptar:    mensagem = cifrado^d   mod n    (chave privada)
```

- Funciona por causa do Teorema de Euler: `(m^e)^d = m^(e*d) mod n = m`
- Mostrar conversão texto → inteiro → cifrado → inteiro → texto
- Demonstração ao vivo: rodar `python3 rsa_lab.py 32` e mostrar o ciclo completo

### Slide 5 — Encriptação por blocos

- RSA só encripta um inteiro menor que `n` por vez
- Para mensagens maiores: divide em blocos de bytes que cabem em `n`
- Cada bloco é encriptado independentemente
- Na decriptação: decripta cada bloco e concatena

```
"Mensagem grande"  →  [Mensag] [em gra] [nde]  →  cifrado₁, cifrado₂, cifrado₃
```

- Tamanho do bloco = `(bits de n - 1) / 8` bytes
- Demonstração: rodar `python3 rsa_lab.py 32` e mostrar a Etapa 2b

### Slide 6 — Formato PEM (como chaves são salvas)

- No mundo real, chaves RSA são salvas em arquivos `.pem`
- O que parece "texto aleatório" é na verdade os números da chave codificados
- Camadas: números → estrutura ASN.1 → bytes DER (Tag-Length-Value) → Base64 → headers PEM

```
-----BEGIN RSA PUBLIC KEY-----
MAsCBEjYimECAwEAAQ==
-----END RSA PUBLIC KEY-----
```

- Demonstração: gerar chave com `python3 rsa_keygen.py 512` e mostrar o PEM

### Slide 7 — Quebrando a chave (ataque)

- O atacante tem a chave pública `(e, n)` — ela é pública!
- Se ele fatorar `n` em `p` e `q`, recalcula `phi` e depois `d`
- Com `d`, tem a chave privada completa

```
n público → fatorar → p, q → phi = (p-1)(q-1) → d = inverso(e, phi)
```

- Tabela de complexidade:

| Chave    | Tempo de fatoração     |
|----------|------------------------|
| 32 bits  | Instantâneo            |
| 64 bits  | ~2 minutos             |
| 128 bits | Séculos                |
| 2048 bits| Impossível             |

- Demonstração ao vivo: quebrar uma chave de 32 bits em tempo real

### Slide 8 — Demonstração ao vivo

Sugestão de roteiro para a demo:

1. `python3 rsa_lab.py 32` — mostra tudo de uma vez (gerar, cifrar, PEM, quebrar)
2. `python3 rsa_cli.py` — CLI interativa, mais visual:
   - Gerar chaves de 64 bits
   - Encriptar uma mensagem longa
   - Encriptar a mesma mensagem em modo raw (Base64)
   - Decriptar
   - Mostrar PEM
   - Quebrar (com chave de 32 bits para ser rápido)

### Slide 9 — Onde RSA aparece no mundo real

- **SSH**: `ssh-keygen -t rsa` gera chaves RSA para autenticação
- **HTTPS/TLS**: certificados SSL usam RSA (ou curvas elípticas)
- **Assinaturas digitais**: assinar documentos, commits git (`git commit -S`)
- **PGP/GPG**: criptografia de email
- RSA geralmente **não** cifra os dados diretamente — cifra uma chave simétrica (AES), e o AES cifra os dados (criptografia híbrida)

### Slide 10 — Resumo

- RSA é matemática: primos, exponenciação modular, inverso modular
- Segurança = dificuldade de fatorar números enormes
- Chave pública encripta, chave privada decripta
- Na prática, chaves de 2048+ bits são seguras
- O código do lab implementa tudo isso do zero em ~400 linhas de Python

---

## Como explicar os algoritmos nomeados

### Algoritmo de Euclides (MDC / GCD)

**O que é:** encontra o maior divisor comum entre dois números.

**Como explicar:** "é uma máquina de trocar — pega dois números, troca o maior pelo resto da divisão, e repete até dar zero."

```
gcd(48, 18):  48 ÷ 18 = resto 12
              18 ÷ 12 = resto 6
              12 ÷ 6  = resto 0  →  MDC = 6
```

**No RSA:** valida que `gcd(e, phi) = 1` — sem isso o inverso modular não existe e a chave não funciona.

### Euclides Estendido

**O que é:** além do MDC, encontra `x` e `y` tais que `a*x + b*y = mdc(a, b)`.

**Como explicar:** "é o Euclides normal com memória — além de calcular o MDC, ele lembra o caminho de volta e descobre quais multiplicadores geraram aquele resultado."

**No RSA:** é o motor que calcula o inverso modular. Quando `mdc = 1`, o `x` encontrado é o inverso.

**Dica para apresentação:** não precisa decorar a recursão. Basta dizer que é uma extensão do Euclides que "volta o caminho" para achar os coeficientes.

### Inverso Modular

**O que é:** dado `e`, encontra `d` tal que `e * d mod phi = 1`.

**Como explicar:** "é como achar o número que, multiplicado por `e`, dá resto 1. É o 'desfazer' da multiplicação em aritmética modular."

```
e = 3, phi = 20
3 * 7 = 21
21 mod 20 = 1  →  d = 7
```

**No RSA:** `d` é a chave privada. Sem o inverso modular, não existe descriptografia.

### Miller-Rabin (teste de primalidade)

**O que é:** teste probabilístico que verifica se um número é primo.

**Como explicar:** "pega um número suspeito, faz vários testes aleatórios. Se falhar em qualquer teste, é composto com certeza. Se passar em todos, é primo com probabilidade altíssima."

**Detalhes para quem perguntar:**
1. Escreve `n-1 = 2^r * d` (tira todos os fatores de 2)
2. Escolhe base aleatória `a`
3. Calcula `a^d mod n`
4. Se der 1 ou n-1, passou nessa rodada
5. Senão, eleva ao quadrado até `r` vezes procurando `n-1`
6. Se nunca achar, `n` é composto

**No RSA:** usado para gerar `p` e `q`. Gera candidato aleatório → testa com Miller-Rabin → se falhar, tenta outro.

**Probabilidade de erro:** com 20 rodadas, a chance de aceitar um composto é menor que `1 em 1.000.000.000.000` — desprezível.

### DER / ASN.1 / TLV

**O que é:** formato binário para serializar dados estruturados.

**Como explicar:** "cada campo é um bloquinho com 3 partes: tipo (o que é), tamanho (quantos bytes tem), valor (os bytes do dado). Tipo-Tamanho-Valor, ou TLV."

```
INTEGER 65537:
  Tag:    02          ← "sou um inteiro"
  Length: 03          ← "tenho 3 bytes"
  Value:  01 00 01    ← 65537 em bytes
```

**No RSA:** é como os números da chave são empacotados antes de virar Base64 e depois PEM.

### PKCS#1

**O que é:** padrão que define a ordem dos campos dentro de uma chave RSA.

**Como explicar:** "é o 'formulário' que diz: primeiro vem a versão, depois n, depois e, depois d, etc. Qualquer ferramenta que lê esse formulário sabe extrair os números."

**Chave pública:** `SEQUENCE { n, e }`
**Chave privada:** `SEQUENCE { version, n, e, d, p, q, dp, dq, coeff }` (9 campos)

---

## Perguntas que podem surgir (e respostas)

### "Por que e = 65537?"

É primo, tem só 2 bits ligados em binário (`10000000000000001`), o que torna a exponenciação modular muito rápida. É o padrão da indústria — OpenSSL, SSH, navegadores, todos usam.

### "O que acontece se p = q?"

O código impede: gera `q` diferente de `p`. Se fossem iguais, `n = p^2` e fatorar seria trivial (basta tirar raiz quadrada).

### "Por que a chave privada tem 5 valores se só precisa de 2?"

Matematicamente, `(d, n)` basta para decriptar. Os extras (`p, q, e`) são guardados por conveniência:
- `p` e `q` permitem otimização via CRT (Chinese Remainder Theorem)
- `e` permite reconstruir a chave pública a partir da privada
- É o que o padrão PKCS#1 espera

### "RSA é lento?"

Sim, comparado com criptografia simétrica. Por isso no mundo real RSA só encripta uma chave simétrica pequena, e o AES faz o trabalho pesado (criptografia híbrida). Mas isso é tema do grupo de criptografia simétrica.

### "Dá pra quebrar RSA de 2048 bits?"

Com tecnologia atual, não. A fatoração levaria mais tempo do que a idade do universo. Computação quântica (algoritmo de Shor) poderia, mas ainda não existe em escala prática.

### "O que é CRT nos campos da chave privada?"

Chinese Remainder Theorem — uma otimização que permite decriptar ~4x mais rápido usando `p` e `q` separadamente em vez de usar `n` direto. O lab calcula os campos CRT (`dp`, `dq`, `coeff`) no PEM mas não usa na decriptação (usa o caminho clássico `c^d mod n` por ser mais didático).

### "O Miller-Rabin pode errar?"

Sim, é probabilístico. Mas com 20 rodadas a chance de falso positivo é menor que 1 em um trilhão. Para uso didático, é mais que suficiente. Na prática, OpenSSL também usa Miller-Rabin.

### "Como o atacante sabe que é RSA?"

Na prática, o protocolo (SSH, TLS) anuncia o algoritmo usado. E o header PEM (`BEGIN RSA PUBLIC KEY`) também indica. A segurança do RSA não depende de esconder o algoritmo — depende de esconder `d`.

### "Por que Base64 e não hex?"

Base64 é mais compacto: 4 caracteres representam 3 bytes (eficiência de 75%), enquanto hex usa 2 caracteres por byte (50%). Para chaves grandes, a diferença importa.

### "A saída encriptada parece só números. Na vida real também?"

Na vida real o cifrado é salvo como bytes binários (ou Base64 quando precisa ser texto). No lab, mostramos os inteiros crus para fins didáticos. O modo `--raw` dos CLIs mostra a versão realista em Base64.

---

## Roteiro de estudo para o grupo

### Prioridade 1 — Entender o fluxo geral

1. Ler a seção "O que é RSA?" e "Etapas do laboratório" no README
2. Rodar `python3 rsa_lab.py 32` e acompanhar cada etapa no terminal
3. Conseguir explicar com suas palavras: geração de chaves → encriptação → decriptação → ataque

### Prioridade 2 — Entender a matemática

1. MDC e inverso modular — fazer na mão com números pequenos (ex: `e=3, phi=20, d=?`)
2. Entender por que `e*d mod phi = 1` garante que decriptar funciona
3. Não precisa decorar Miller-Rabin — basta saber que é um teste probabilístico de primalidade

### Prioridade 3 — Saber navegar o código

1. Abrir `rsa_core.py` e localizar cada função
2. Acompanhar o fluxo: `generate_keys` → `generate_prime` → `is_prime_miller_rabin`
3. Usar o "Mapa de funções" do README como referência rápida

### Prioridade 4 — Entender PEM (se perguntarem)

1. Saber que PEM = números → DER (binário TLV) → Base64 → headers
2. Não precisa decorar bytes — basta entender o conceito de camadas
3. Saber que PKCS#1 define a ordem dos campos

### O que NÃO precisa estudar

- Implementação detalhada do DER (ninguém vai pedir pra escrever TLV na mão)
- Curvas elípticas, Diffie-Hellman, AES (são temas de outros grupos)
- Detalhes de otimização CRT (basta saber que existe e pra que serve)

---

## Dicas para a apresentação

1. **Comece pela analogia do cadeado**, não pela matemática. A plateia entende "cadeado aberto = chave pública" antes de entender "exponenciação modular".

2. **Demo ao vivo impressiona.** Rodar o lab e mostrar a chave sendo quebrada em tempo real é mais impactante do que qualquer slide.

3. **Prepare a demo antes.** Rode `python3 rsa_lab.py 32` pelo menos uma vez para garantir que funciona no computador da apresentação. Se possível, use a CLI interativa (`rsa_cli.py`).

4. **Divida os tópicos no grupo.** Sugestão:
   - Pessoa 1: conceito de criptografia assimétrica + por que RSA funciona
   - Pessoa 2: geração de chaves (primos, MDC, inverso modular)
   - Pessoa 3: criptografia/descriptografia + encriptação por blocos
   - Pessoa 4: formato PEM (camadas, DER, Base64) + demonstração ao vivo
   - Pessoa 5: ataque por fatoração + tabela de complexidade + por que chaves grandes são seguras

5. **Se alguém perguntar algo que você não sabe**, diga "essa é uma boa pergunta, vou verificar" — é melhor do que inventar.

6. **Não tente explicar todo o código.** Foque no fluxo e nos conceitos. O código é a prova de que funciona, não o objetivo da apresentação.

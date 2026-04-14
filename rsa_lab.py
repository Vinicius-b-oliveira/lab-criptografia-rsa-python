#!/usr/bin/env python3
"""
=============================================================================
 LABORATÓRIO DE CRIPTOGRAFIA ASSIMÉTRICA RSA
=============================================================================

 Este script implementa o algoritmo RSA do zero, sem bibliotecas externas
 de criptografia, com fins puramente educacionais.

 O que este lab cobre:
   1. Fundamentos matemáticos (MDC, inverso modular, teste de primalidade)
   2. Geração de chaves pública e privada
   3. Criptografia e descriptografia de mensagens
   4. Exportação das chaves em formato PEM (ASN.1/DER + Base64)
   5. Quebra da chave privada por fatoração (ataque)

 Uso: python3 rsa_lab.py [bits]
     bits = 16, 32, 64, 128, 256, 512, 1024 (padrão: 16)

=============================================================================

 CONCEITOS FUNDAMENTAIS
 ----------------------

 O RSA se baseia em um fato matemático simples:
   - Multiplicar dois primos grandes é fácil:  p * q = n  (instantâneo)
   - Fatorar o resultado de volta é difícil:   n = ? * ? (pode levar séculos)

 Essa assimetria entre multiplicação (fácil) e fatoração (difícil) é o que
 torna o RSA seguro. Quem conhece p e q consegue descriptografar. Quem só
 conhece n (= p*q) precisaria fatorar n para descobrir p e q, o que é
 computacionalmente inviável para números grandes (2048+ bits).

=============================================================================
"""

import math
import secrets
import base64
import sys
import time


# =============================================================================
# SEÇÃO 1: FUNDAMENTOS MATEMÁTICOS
# =============================================================================
#
# Antes de implementar o RSA, precisamos de quatro ferramentas matemáticas:
#   1. MDC (Máximo Divisor Comum) — para verificar coprimalidade
#   2. Inverso Modular — para calcular a chave privada
#   3. Teste de Primalidade — para verificar se um número é primo
#   4. Geração de Primos — para gerar p e q
#


def gcd(a, b):
    """
    Calcula o Máximo Divisor Comum usando o Algoritmo de Euclides.

    O algoritmo funciona por substituições sucessivas:
      gcd(48, 18) -> gcd(18, 12) -> gcd(12, 6) -> gcd(6, 0) -> 6

    A cada passo, substituímos (a, b) por (b, a % b) até b ser zero.
    Quando b == 0, o MDC é a.

    No RSA, usamos o MDC para garantir que 'e' e 'phi(n)' são coprimos,
    ou seja, gcd(e, phi(n)) == 1. Isso é necessário para que o inverso
    modular de 'e' exista (sem ele, não há chave privada).

    Nota: Python tem math.gcd(), mas implementamos aqui para fins didáticos.
    """
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """
    Algoritmo de Euclides Estendido.

    Além de calcular gcd(a, b), encontra x e y tais que:
        a*x + b*y = gcd(a, b)

    Isso é essencial para calcular o inverso modular.

    Exemplo passo a passo com a=35, b=15:
      extended_gcd(35, 15):
        extended_gcd(15, 5):
          extended_gcd(5, 0):
            retorna (5, 1, 0)    -> 5 = 5*1 + 0*0
          retorna (5, 0, 1)      -> 5 = 15*0 + 5*1
        retorna (5, 1, -2)       -> 5 = 35*1 + 15*(-2)

    A ideia: voltamos da recursão "desfazendo" as divisões, reconstruindo
    os coeficientes x e y a cada passo.
    """
    if a == 0:
        return b, 0, 1

    # Chamada recursiva com os mesmos passos do Euclides clássico
    g, x, y = extended_gcd(b % a, a)

    # Reconstrói os coeficientes ao voltar da recursão
    # Se (b%a)*x + a*y = g, então a*(y - (b//a)*x) + b*x = g
    return g, y - (b // a) * x, x


def mod_inverse(e, phi):
    """
    Calcula o inverso modular de 'e' módulo 'phi'.

    Encontra 'd' tal que: (e * d) % phi == 1

    Isso significa que 'd' é o número que, multiplicado por 'e',
    dá resto 1 na divisão por phi.

    Exemplo: se e=3 e phi=20:
      3 * 7 = 21, e 21 % 20 = 1
      Portanto, d = 7

    Por que isso importa no RSA?
    ----------------------------
    A criptografia RSA funciona porque:
      - Criptografar:    cifrado = mensagem^e mod n
      - Descriptografar: mensagem = cifrado^d mod n

    Para que uma operação desfaça a outra, precisamos que e*d ≡ 1 (mod phi(n)).
    Essa relação garante, pelo Teorema de Euler, que:
      (mensagem^e)^d = mensagem^(e*d) = mensagem^(1 + k*phi(n)) ≡ mensagem (mod n)

    Usamos o Algoritmo de Euclides Estendido para encontrar 'd'.
    Se gcd(e, phi) != 1, o inverso não existe (e 'e' foi mal escolhido).
    """
    g, x, _ = extended_gcd(e % phi, phi)

    if g != 1:
        raise ValueError(
            f"Inverso modular não existe: gcd({e}, {phi}) = {g} (deveria ser 1)"
        )

    # x pode ser negativo, ajustamos para ficar no intervalo [0, phi)
    return x % phi


def is_prime_miller_rabin(n, rounds=20):
    """
    Teste de primalidade de Miller-Rabin (probabilístico).

    Para números pequenos (< 2000), usamos divisão por tentativa.
    Para números grandes, usamos Miller-Rabin.

    Como funciona o Miller-Rabin:
    -----------------------------
    Dado um número ímpar n, escrevemos n-1 = 2^r * d (fatoramos os 2s).

    Para uma base aleatória 'a', calculamos:
      x = a^d mod n

    Se x == 1 ou x == n-1, n "parece primo" para essa base.
    Caso contrário, elevamos x ao quadrado até r vezes:
      x = x^2 mod n

    Se em algum momento x == n-1, n "parece primo".
    Se chegarmos ao fim sem encontrar n-1, n é COMPOSTO (com certeza).

    A cada rodada com base aleatória, a chance de erro é <= 1/4.
    Com 20 rodadas, a chance de um composto passar é <= (1/4)^20 ≈ 10^-12.

    Por que não testar todos os divisores?
    --------------------------------------
    Para um número de 512 bits, teríamos que testar ~10^77 divisores.
    O Miller-Rabin dá uma resposta confiável em milissegundos.
    """
    # Casos triviais
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Para números pequenos, divisão por tentativa é suficiente
    if n < 2000:
        for i in range(3, int(math.isqrt(n)) + 1, 2):
            if n % i == 0:
                return False
        return True

    # Escreve n-1 como 2^r * d (remove fatores de 2)
    # Exemplo: se n=13, n-1=12=2^2*3, então r=2 e d=3
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Testa com 'rounds' bases aleatórias
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # base aleatória em [2, n-2]
        x = pow(a, d, n)  # a^d mod n (exponenciação modular eficiente)

        if x == 1 or x == n - 1:
            continue  # "parece primo" para esta base

        is_composite = True
        for _ in range(r - 1):
            x = pow(x, 2, n)  # x = x^2 mod n
            if x == n - 1:
                is_composite = False  # encontrou n-1, "parece primo"
                break

        if is_composite:
            return False  # com certeza é composto

    return True  # provavelmente primo (com altíssima confiança)


def generate_prime(bits):
    """
    Gera um número primo aleatório com o número de bits especificado.

    Estratégia:
    1. Gera um número aleatório ímpar com 'bits' bits
    2. Testa se é primo com Miller-Rabin
    3. Se não for, incrementa de 2 em 2 (mantendo ímpar) e testa de novo
    4. Repete até encontrar um primo

    O bit mais significativo é forçado a 1 para garantir que o número
    realmente tem 'bits' bits (e não menos). Exemplo para 8 bits:
      - Queremos números entre 10000000 (128) e 11111111 (255)
      - Se não forçássemos, poderíamos gerar 00001011 (11), que tem só 4 bits

    Pelo Teorema dos Números Primos, a densidade de primos perto de N
    é aproximadamente 1/ln(N). Para 512 bits, isso é ~1/355, então
    em média testamos ~355 candidatos antes de encontrar um primo.
    """
    while True:
        # Gera número aleatório com 'bits' bits
        # secrets.randbits() gera bits aleatórios criptograficamente seguros
        n = secrets.randbits(bits)

        # Força o bit mais significativo (garante que tem 'bits' bits)
        n |= (1 << (bits - 1))

        # Força o bit menos significativo (garante que é ímpar)
        n |= 1

        if is_prime_miller_rabin(n):
            return n


# =============================================================================
# SEÇÃO 2: GERAÇÃO DE CHAVES RSA
# =============================================================================
#
# O processo de geração de chaves:
#
#   1. Gera dois primos aleatórios p e q
#   2. Calcula n = p * q                 (módulo — parte pública)
#   3. Calcula phi(n) = (p-1) * (q-1)    (totiente de Euler — secreto!)
#   4. Escolhe e (expoente público)       (geralmente 65537)
#   5. Calcula d = inverso(e, phi(n))     (expoente privado — secreto!)
#
# Resultado:
#   Chave pública:  (e, n)  — qualquer um pode ter
#   Chave privada:  (d, n)  — somente o dono
#
# Por que phi(n)?
# ---------------
# phi(n) conta quantos números de 1 a n são coprimos com n.
# Para n = p*q (com p e q primos), phi(n) = (p-1)*(q-1).
#
# O Teorema de Euler diz que: a^phi(n) ≡ 1 (mod n)
# Isso garante que criptografar e descriptografar são operações inversas:
#   (m^e)^d = m^(e*d) = m^(1 + k*phi(n)) = m * (m^phi(n))^k ≡ m * 1^k = m (mod n)
#


def generate_keys(bits):
    """
    Gera um par de chaves RSA com o tamanho especificado.

    Parâmetros:
        bits: tamanho em bits de cada primo (a chave terá ~2*bits de tamanho)
              Exemplo: bits=512 gera chave de ~1024 bits

    Retorna:
        public_key:  tupla (e, n)
        private_key: tupla (d, n, p, q, e)
            Guardamos p, q e e na chave privada porque:
            - p e q são usados para otimização (CRT - Chinese Remainder Theorem)
            - São necessários para o formato PEM padrão
            - e é incluído por conveniência (formato PKCS#1 exige)

    Sobre o expoente público 'e':
    -----------------------------
    Usamos e = 65537 (0x10001 em hexadecimal), que é o padrão da indústria.
    Por que 65537?
      - É primo (necessário para gcd(e, phi) = 1 funcionar na maioria dos casos)
      - Em binário é 10000000000000001 (só dois bits 1)
      - Isso torna a exponenciação modular muito rápida (poucas multiplicações)
      - Grande o suficiente para ser seguro contra certos ataques
      - Outros valores comuns históricos: 3, 17 (menos seguros)
    """
    print(f"\n{'='*60}")
    print(f"  GERANDO CHAVES RSA ({bits * 2} bits)")
    print(f"{'='*60}")

    # Passo 1: Gerar dois primos distintos
    print(f"\n[1] Gerando primo p ({bits} bits)...")
    p = generate_prime(bits)
    print(f"    p = {p}")
    if bits <= 32:
        print(f"    p em binário: {bin(p)}")

    print(f"\n[2] Gerando primo q ({bits} bits)...")
    q = generate_prime(bits)
    # Garante que p != q (extremamente improvável para primos grandes,
    # mas para 16 bits é possível)
    while q == p:
        q = generate_prime(bits)
    print(f"    q = {q}")
    if bits <= 32:
        print(f"    q em binário: {bin(q)}")

    # Passo 2: Calcular n = p * q
    # n é o módulo, usado tanto na chave pública quanto na privada
    # O tamanho de n determina o "tamanho da chave" (ex: RSA-2048 usa n de 2048 bits)
    n = p * q
    print(f"\n[3] Calculando n = p * q")
    print(f"    n = {p} * {q}")
    print(f"    n = {n}")
    print(f"    Tamanho de n: {n.bit_length()} bits")

    # Passo 3: Calcular phi(n) = (p-1) * (q-1)
    # phi(n) é a função totiente de Euler
    # IMPORTANTE: phi(n) deve permanecer SECRETO!
    # Se alguém descobrir phi(n), pode calcular d e quebrar a chave.
    phi_n = (p - 1) * (q - 1)
    print(f"\n[4] Calculando phi(n) = (p-1) * (q-1)")
    print(f"    phi(n) = ({p}-1) * ({q}-1)")
    print(f"    phi(n) = {p - 1} * {q - 1}")
    print(f"    phi(n) = {phi_n}")

    # Passo 4: Escolher o expoente público 'e'
    e = 65537
    # Para chaves muito pequenas, 65537 pode ser >= phi(n)
    # Nesse caso, escolhemos o maior primo que funcione
    if e >= phi_n:
        for candidate in [257, 17, 5, 3]:
            if candidate < phi_n and gcd(candidate, phi_n) == 1:
                e = candidate
                break
    print(f"\n[5] Escolhendo expoente público 'e'")
    print(f"    e = {e}")
    print(f"    Verificando: gcd(e, phi(n)) = gcd({e}, {phi_n}) = {gcd(e, phi_n)}")

    # Passo 5: Calcular o expoente privado 'd'
    # d é o inverso modular de e mod phi(n)
    # Ou seja: (e * d) % phi(n) == 1
    d = mod_inverse(e, phi_n)
    print(f"\n[6] Calculando expoente privado 'd' (inverso modular de e)")
    print(f"    d = mod_inverse({e}, {phi_n})")
    print(f"    d = {d}")
    print(f"    Verificação: (e * d) % phi(n) = ({e} * {d}) % {phi_n} = {(e * d) % phi_n}")

    # Montar as chaves
    public_key = (e, n)
    # A chave privada inclui p, q e e para o formato PEM e otimizações
    private_key = (d, n, p, q, e)

    print(f"\n{'─'*60}")
    print(f"  CHAVES GERADAS COM SUCESSO")
    print(f"{'─'*60}")
    print(f"  Chave Pública  (e, n): qualquer pessoa pode ter")
    print(f"    e = {e}")
    print(f"    n = {n}")
    print(f"\n  Chave Privada  (d, n): somente o dono deve ter")
    print(f"    d = {d}")
    print(f"    n = {n}")
    print(f"{'─'*60}")

    return public_key, private_key


# =============================================================================
# SEÇÃO 3: CRIPTOGRAFIA E DESCRIPTOGRAFIA
# =============================================================================
#
# A beleza do RSA está na simplicidade das operações:
#
#   Criptografar:    cifrado  = mensagem^e mod n   (usa chave pública)
#   Descriptografar: mensagem = cifrado^d  mod n   (usa chave privada)
#
# Para criptografar texto, precisamos converter letras em números.
# Cada caractere tem um código (UTF-8), e concatenamos esses códigos
# para formar um único número grande que será criptografado.
#
# LIMITAÇÃO IMPORTANTE:
# O número da mensagem deve ser MENOR que n. Se a mensagem for maior,
# ela precisa ser dividida em blocos. No mundo real, o RSA raramente
# criptografa mensagens diretamente — ele criptografa uma chave simétrica
# (AES), e a mensagem é criptografada com AES. Isso se chama
# "criptografia híbrida".
#


def encrypt(message_int, public_key):
    """
    Criptografa um número inteiro usando a chave pública.

    Operação matemática:
        ciphertext = message ^ e  mod n

    Python usa pow(base, exp, mod) que implementa "exponenciação modular
    rápida" (square-and-multiply), evitando calcular o número gigante
    message^e antes de aplicar o módulo.

    Parâmetros:
        message_int: número inteiro representando a mensagem (deve ser < n)
        public_key: tupla (e, n)

    Retorna:
        ciphertext: número inteiro criptografado
    """
    e, n = public_key

    if message_int >= n:
        raise ValueError(
            f"Mensagem ({message_int}) deve ser menor que n ({n}). "
            f"Use uma chave maior ou divida a mensagem em blocos."
        )

    # A operação fundamental do RSA: exponenciação modular
    ciphertext = pow(message_int, e, n)
    return ciphertext


def decrypt(ciphertext, private_key):
    """
    Descriptografa um número inteiro usando a chave privada.

    Operação matemática:
        message = ciphertext ^ d  mod n

    Isso funciona por causa do Teorema de Euler:
        ciphertext^d = (message^e)^d = message^(e*d) mod n

    Como e*d ≡ 1 (mod phi(n)), temos e*d = 1 + k*phi(n) para algum k.
    Portanto:
        message^(1 + k*phi(n)) = message * (message^phi(n))^k

    Pelo Teorema de Euler, message^phi(n) ≡ 1 (mod n), logo:
        message * 1^k = message (mod n)

    Parâmetros:
        ciphertext: número inteiro criptografado
        private_key: tupla (d, n, p, q, e) — usamos apenas d e n

    Retorna:
        message_int: número inteiro original
    """
    d, n = private_key[0], private_key[1]
    message_int = pow(ciphertext, d, n)
    return message_int


def text_to_int(text):
    """
    Converte uma string de texto em um número inteiro.

    Processo:
    1. Converte o texto em bytes usando UTF-8
    2. Interpreta esses bytes como um número inteiro (big-endian)

    Exemplo: "Hi" -> bytes [72, 105] -> 0x4869 -> 18537

    Big-endian significa que o byte mais significativo vem primeiro,
    assim como escrevemos números decimais (o dígito mais importante
    vem à esquerda).
    """
    data = text.encode("utf-8")
    return int.from_bytes(data, byteorder="big")


def int_to_text(number):
    """
    Converte um número inteiro de volta para uma string de texto.

    Processo inverso:
    1. Calcula quantos bytes o número precisa
    2. Converte o inteiro em bytes (big-endian)
    3. Decodifica os bytes como UTF-8

    Exemplo: 18537 -> bytes [72, 105] -> "Hi"
    """
    byte_length = (number.bit_length() + 7) // 8
    data = number.to_bytes(byte_length, byteorder="big")
    return data.decode("utf-8")


def demo_encryption(public_key, private_key, message=None):
    """
    Demonstra o processo completo de criptografia e descriptografia.

    Mostra cada etapa: texto -> número -> cifrado -> número -> texto
    """
    _, n = public_key
    n_bits = n.bit_length()

    # Escolhe uma mensagem adequada ao tamanho da chave
    if message is None:
        if n_bits < 16:
            message = "A"  # chave muito pequena, cabe pouco
        elif n_bits < 32:
            message = "Hi"
        elif n_bits < 64:
            message = "RSA!"
        elif n_bits < 256:
            message = "Seguranca!"
        else:
            message = "RSA é incrível! Criptografia assimétrica funciona."

    print(f"\n{'='*60}")
    print(f"  CRIPTOGRAFIA E DESCRIPTOGRAFIA")
    print(f"{'='*60}")

    # Passo 1: Texto -> Inteiro
    msg_int = text_to_int(message)
    print(f"\n[1] Mensagem original: \"{message}\"")
    print(f"    Bytes (UTF-8):     {list(message.encode('utf-8'))}")
    print(f"    Como inteiro:      {msg_int}")

    if msg_int >= n:
        # Mensagem grande demais para essa chave, trunca
        message = message[:max(1, (n_bits // 8) - 1)]
        msg_int = text_to_int(message)
        print(f"\n    [!] Mensagem truncada para caber na chave: \"{message}\"")
        print(f"    Como inteiro:      {msg_int}")

    # Passo 2: Criptografar
    ciphertext = encrypt(msg_int, public_key)
    e, n = public_key
    print(f"\n[2] Criptografando: ciphertext = message^e mod n")
    print(f"    ciphertext = {msg_int}^{e} mod {n}")
    print(f"    ciphertext = {ciphertext}")

    # Passo 3: Descriptografar
    d = private_key[0]
    decrypted = decrypt(ciphertext, private_key)
    print(f"\n[3] Descriptografando: message = ciphertext^d mod n")
    print(f"    message = {ciphertext}^{d} mod {n}")
    print(f"    message = {decrypted}")

    # Passo 4: Inteiro -> Texto
    recovered_text = int_to_text(decrypted)
    print(f"\n[4] Convertendo inteiro de volta para texto:")
    print(f"    Inteiro:  {decrypted}")
    print(f"    Texto:    \"{recovered_text}\"")

    # Verificação
    success = recovered_text == message
    print(f"\n[5] Verificação: mensagem original == mensagem recuperada?")
    print(f"    \"{message}\" == \"{recovered_text}\" -> {'SUCESSO!' if success else 'FALHA!'}")

    return success


# =============================================================================
# SEÇÃO 4: FORMATO PEM (ASN.1/DER + BASE64)
# =============================================================================
#
# Quando você vê uma chave RSA em um arquivo, ela se parece com isso:
#
#   -----BEGIN RSA PRIVATE KEY-----
#   MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyu...
#   -----END RSA PRIVATE KEY-----
#
# Essa "string aleatória" NÃO é aleatória. Ela é a chave (números inteiros)
# codificada em três camadas:
#
#   1. ASN.1 (Abstract Syntax Notation One):
#      Um padrão que define a ESTRUTURA dos dados.
#      "Esta chave contém: versão, módulo, expoente público, expoente privado..."
#
#   2. DER (Distinguished Encoding Rules):
#      Regras para converter a estrutura ASN.1 em BYTES.
#      Usa formato TLV (Tag-Length-Value):
#        [Tag: tipo do dado][Length: quantos bytes][Value: os bytes do dado]
#
#   3. Base64:
#      Converte os bytes binários em texto ASCII imprimível.
#      Cada 3 bytes viram 4 caracteres do alfabeto A-Z, a-z, 0-9, +, /
#
#   4. PEM (Privacy-Enhanced Mail):
#      Adiciona cabeçalhos "-----BEGIN/END-----" ao redor do Base64.
#      É o formato final do arquivo.
#
# Fluxo completo:
#   números inteiros -> estrutura ASN.1 -> bytes DER -> texto Base64 -> arquivo PEM
#


def encode_der_length(length):
    """
    Codifica o campo "Length" do formato DER (TLV).

    Regras DER para o campo Length:
    - Se length < 128 (0x80): um único byte com o valor
    - Se length >= 128: primeiro byte indica quantos bytes de tamanho seguem

    Exemplos:
      length=5     -> b'\\x05'          (1 byte: o próprio valor)
      length=200   -> b'\\x81\\xc8'      (0x81 = "1 byte de tamanho segue", 0xc8 = 200)
      length=1000  -> b'\\x82\\x03\\xe8'  (0x82 = "2 bytes de tamanho seguem", 0x03e8 = 1000)

    O bit mais significativo do primeiro byte (0x80) funciona como flag:
      0xxxxxxx = tamanho curto (o próprio byte é o tamanho)
      1xxxxxxx = tamanho longo (os 7 bits baixos dizem quantos bytes seguem)
    """
    if length < 0x80:
        return bytes([length])
    else:
        # Calcula quantos bytes são necessários para representar o tamanho
        byte_count = (length.bit_length() + 7) // 8
        # Primeiro byte: 0x80 | número de bytes que seguem
        return bytes([0x80 | byte_count]) + length.to_bytes(byte_count, "big")


def int_to_der(value):
    """
    Codifica um número inteiro no formato DER.

    Formato TLV:
      Tag (0x02 = INTEGER) + Length + Value (o número em bytes, big-endian)

    Detalhe importante: DER usa inteiros com sinal (complemento de dois).
    Se o bit mais significativo do número for 1, precisamos adicionar um
    byte 0x00 na frente para indicar que o número é positivo.

    Exemplo: número 128 = 0x80 em bytes
      Sem padding: 0x80 seria interpretado como -128 (negativo!)
      Com padding: 0x00 0x80 é corretamente interpretado como +128
    """
    if value == 0:
        content = b"\x00"
    else:
        byte_length = (value.bit_length() + 7) // 8
        content = value.to_bytes(byte_length, "big")
        # Adiciona byte zero se o bit mais significativo estiver setado
        # para evitar interpretação como número negativo
        if content[0] & 0x80:
            content = b"\x00" + content

    return b"\x02" + encode_der_length(len(content)) + content


def der_sequence(content):
    """
    Empacota dados em uma SEQUENCE DER.

    SEQUENCE é o "container" do ASN.1 — agrupa vários elementos.
    Tag 0x30 = SEQUENCE (construído).

    Uma chave RSA é uma SEQUENCE contendo vários INTEGERs:
      SEQUENCE {
        INTEGER (versão),
        INTEGER (módulo n),
        INTEGER (expoente público e),
        ...
      }
    """
    return b"\x30" + encode_der_length(len(content)) + content


def private_key_to_pem(private_key):
    """
    Converte a chave privada para o formato PEM (PKCS#1).

    Formato PKCS#1 para chave privada RSA (RFC 3447):
    RSAPrivateKey ::= SEQUENCE {
        version           INTEGER,  -- 0 (two-prime)
        modulus           INTEGER,  -- n
        publicExponent    INTEGER,  -- e
        privateExponent   INTEGER,  -- d
        prime1            INTEGER,  -- p
        prime2            INTEGER,  -- q
        exponent1         INTEGER,  -- d mod (p-1), usado para otimização CRT
        exponent2         INTEGER,  -- d mod (q-1), usado para otimização CRT
        coefficient       INTEGER   -- q^(-1) mod p, usado para otimização CRT
    }

    CRT (Chinese Remainder Theorem) permite descriptografar ~4x mais rápido
    usando p e q separadamente em vez de n diretamente. Por isso o formato
    inclui esses valores pré-calculados.
    """
    d, n, p, q, e = private_key

    # Valores CRT pré-calculados (otimização)
    exp1 = d % (p - 1)     # dP: d mod (p-1)
    exp2 = d % (q - 1)     # dQ: d mod (q-1)
    coeff = mod_inverse(q, p)  # qInv: q^(-1) mod p

    # Monta a SEQUENCE com todos os campos
    content = b"".join([
        int_to_der(0),      # version = 0
        int_to_der(n),      # modulus
        int_to_der(e),      # publicExponent
        int_to_der(d),      # privateExponent
        int_to_der(p),      # prime1
        int_to_der(q),      # prime2
        int_to_der(exp1),   # exponent1 (CRT)
        int_to_der(exp2),   # exponent2 (CRT)
        int_to_der(coeff),  # coefficient (CRT)
    ])

    # Empacota em uma SEQUENCE
    der = der_sequence(content)

    # Converte para Base64 com linhas de 64 caracteres (padrão PEM)
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]

    # Monta o bloco PEM com cabeçalhos
    pem = "-----BEGIN RSA PRIVATE KEY-----\n"
    pem += "\n".join(lines) + "\n"
    pem += "-----END RSA PRIVATE KEY-----\n"

    return pem


def public_key_to_pem(public_key):
    """
    Converte a chave pública para o formato PEM (PKCS#1).

    Formato PKCS#1 para chave pública RSA (RFC 3447):
    RSAPublicKey ::= SEQUENCE {
        modulus           INTEGER,  -- n
        publicExponent    INTEGER   -- e
    }

    Muito mais simples que a chave privada — apenas dois campos.
    """
    e, n = public_key

    content = int_to_der(n) + int_to_der(e)
    der = der_sequence(content)

    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]

    pem = "-----BEGIN RSA PUBLIC KEY-----\n"
    pem += "\n".join(lines) + "\n"
    pem += "-----END RSA PUBLIC KEY-----\n"

    return pem


def demo_pem_format(public_key, private_key):
    """
    Demonstra a conversão das chaves para formato PEM.
    Mostra o processo camada por camada.
    """
    print(f"\n{'='*60}")
    print(f"  FORMATO PEM (ASN.1/DER + Base64)")
    print(f"{'='*60}")

    print(f"\n  Fluxo de codificação:")
    print(f"  números inteiros")
    print(f"      |")
    print(f"      v")
    print(f"  estrutura ASN.1 (define quais campos e tipos)")
    print(f"      |")
    print(f"      v")
    print(f"  bytes DER (formato binário TLV: Tag-Length-Value)")
    print(f"      |")
    print(f"      v")
    print(f"  texto Base64 (binário -> ASCII imprimível)")
    print(f"      |")
    print(f"      v")
    print(f"  bloco PEM (Base64 + cabeçalhos BEGIN/END)")

    # Mostra chave pública PEM
    pem_pub = public_key_to_pem(public_key)
    print(f"\n{'─'*60}")
    print(f"  CHAVE PÚBLICA (PEM / PKCS#1):")
    print(f"{'─'*60}")
    print(f"\n  Estrutura ASN.1:")
    print(f"  SEQUENCE {{")
    print(f"    modulus         INTEGER  -- n = {public_key[1]}")
    print(f"    publicExponent  INTEGER  -- e = {public_key[0]}")
    print(f"  }}")
    print(f"\n  Arquivo PEM resultante:")
    for line in pem_pub.strip().split("\n"):
        print(f"  {line}")

    # Mostra chave privada PEM
    pem_priv = private_key_to_pem(private_key)
    d, n, p, q, e = private_key
    print(f"\n{'─'*60}")
    print(f"  CHAVE PRIVADA (PEM / PKCS#1):")
    print(f"{'─'*60}")
    print(f"\n  Estrutura ASN.1:")
    print(f"  SEQUENCE {{")
    print(f"    version          INTEGER  -- 0")
    print(f"    modulus          INTEGER  -- n = {n}")
    print(f"    publicExponent   INTEGER  -- e = {e}")
    print(f"    privateExponent  INTEGER  -- d = {d}")
    print(f"    prime1           INTEGER  -- p = {p}")
    print(f"    prime2           INTEGER  -- q = {q}")
    print(f"    exponent1        INTEGER  -- d mod (p-1) = {d % (p - 1)}")
    print(f"    exponent2        INTEGER  -- d mod (q-1) = {d % (q - 1)}")
    print(f"    coefficient      INTEGER  -- q^(-1) mod p = {mod_inverse(q, p)}")
    print(f"  }}")
    print(f"\n  Arquivo PEM resultante:")
    for line in pem_priv.strip().split("\n"):
        print(f"  {line}")

    # Mostra o DER em hexadecimal para a chave pública (mais curta)
    e_pub, n_pub = public_key
    content = int_to_der(n_pub) + int_to_der(e_pub)
    der = der_sequence(content)
    hex_der = der.hex()
    print(f"\n{'─'*60}")
    print(f"  ANATOMIA DO DER (chave pública em hexadecimal):")
    print(f"{'─'*60}")
    print(f"\n  Bytes DER (hex): {hex_der}")
    print(f"\n  Decompondo Tag-Length-Value:")
    print(f"  30 = Tag SEQUENCE (container)")
    print(f"  02 = Tag INTEGER")
    print(f"  Cada campo segue o padrão: [02][tamanho][valor em bytes]")

    return pem_pub, pem_priv


# =============================================================================
# SEÇÃO 5: QUEBRANDO O RSA (ATAQUE POR FATORAÇÃO)
# =============================================================================
#
# O cenário do ataque:
#   - O atacante tem a CHAVE PÚBLICA (e, n) — ela é pública, qualquer um tem
#   - O atacante quer descobrir a CHAVE PRIVADA (d)
#   - Para calcular d, precisa de phi(n) = (p-1)*(q-1)
#   - Para calcular phi(n), precisa de p e q
#   - p e q são os fatores primos de n
#   - Portanto: FATORAR n = QUEBRAR a chave
#
# Para chaves pequenas (16-64 bits), isso leva milissegundos.
# Para chaves reais (2048+ bits), levaria milhões de anos.
#
# Métodos de fatoração:
#   - Divisão por tentativa: testa todos os divisores até sqrt(n)
#     Simples mas lento: O(sqrt(n)) = O(2^(bits/2))
#
#   - Algoritmos avançados (não implementados aqui):
#     - Crivo Quadrático
#     - GNFS (General Number Field Sieve) — o mais rápido conhecido
#     - Algoritmo de Shor (quântico) — quebraria RSA em tempo polinomial
#


def factorize(n):
    """
    Fatora n em seus dois fatores primos p e q.

    Método: divisão por tentativa (trial division).
    Testa todos os números ímpares de 3 até sqrt(n).

    Complexidade: O(sqrt(n)), que para n de b bits é O(2^(b/2)).
      - n de 32 bits:   ~65.000 tentativas (instantâneo)
      - n de 64 bits:   ~4 bilhões (segundos)
      - n de 128 bits:  ~10^19 (séculos)
      - n de 2048 bits: ~10^308 (impossível)

    No mundo real, usam-se algoritmos muito mais sofisticados,
    mas para o lab com chaves pequenas, este método é perfeito
    para demonstrar o conceito.
    """
    # Testa se é par
    if n % 2 == 0:
        return 2, n // 2

    # Testa divisores ímpares até sqrt(n)
    limit = math.isqrt(n) + 1
    attempts = 0

    for i in range(3, limit, 2):
        attempts += 1
        if n % i == 0:
            return i, n // i, attempts

    # Se chegou aqui, n é primo (não deveria acontecer no RSA)
    return n, 1, attempts


def break_key(public_key):
    """
    Dado apenas a chave pública (e, n), reconstrói a chave privada.

    Este é o ataque completo:
    1. Extrai n da chave pública
    2. Fatora n para encontrar p e q
    3. Calcula phi(n) = (p-1) * (q-1)
    4. Calcula d = mod_inverse(e, phi(n))
    5. Pronto! Temos a chave privada (d, n)

    Com a chave privada, podemos descriptografar qualquer mensagem
    que foi criptografada com a chave pública correspondente.
    """
    e, n = public_key

    print(f"\n{'='*60}")
    print(f"  QUEBRANDO A CHAVE RSA (ataque por fatoração)")
    print(f"{'='*60}")

    print(f"\n  Cenário: o atacante tem a chave pública (e={e}, n={n})")
    print(f"  Objetivo: descobrir a chave privada (d, n)")
    print(f"  Estratégia: fatorar n para encontrar p e q")
    print(f"\n  Tamanho de n: {n.bit_length()} bits")

    if n.bit_length() > 64:
        print(f"\n  [!] AVISO: chave com {n.bit_length()} bits.")
        print(f"  A fatoração por divisão por tentativa pode demorar.")
        print(f"  No mundo real com 2048+ bits, isso seria IMPOSSÍVEL.")

    print(f"\n[1] Fatorando n = {n}...")
    start = time.time()
    result = factorize(n)
    elapsed = time.time() - start

    if len(result) == 3:
        p, q, attempts = result
    else:
        p, q = result
        attempts = "?"

    print(f"    Fatores encontrados!")
    print(f"    p = {p}")
    print(f"    q = {q}")
    print(f"    Verificação: p * q = {p} * {q} = {p * q} {'== n OK' if p * q == n else '!= n ERRO'}")
    print(f"    Tentativas: {attempts}")
    print(f"    Tempo: {elapsed:.6f} segundos")

    print(f"\n[2] Calculando phi(n) = (p-1) * (q-1)")
    phi_n = (p - 1) * (q - 1)
    print(f"    phi(n) = ({p}-1) * ({q}-1) = {phi_n}")

    print(f"\n[3] Calculando d = mod_inverse(e, phi(n))")
    d = mod_inverse(e, phi_n)
    print(f"    d = mod_inverse({e}, {phi_n})")
    print(f"    d = {d}")

    recovered_private_key = (d, n, p, q, e)

    print(f"\n{'─'*60}")
    print(f"  CHAVE PRIVADA RECUPERADA COM SUCESSO!")
    print(f"{'─'*60}")
    print(f"  d = {d}")
    print(f"  n = {n}")
    print(f"\n  O atacante agora pode descriptografar qualquer mensagem")
    print(f"  criptografada com a chave pública correspondente.")
    print(f"{'─'*60}")

    return recovered_private_key


def demo_full_attack(public_key, original_private_key):
    """
    Demonstra o ataque completo: interceptar, quebrar e descriptografar.
    """
    _, n = public_key
    n_bits = n.bit_length()

    # Escolhe mensagem secreta adequada ao tamanho
    if n_bits < 16:
        secret_message = "A"
    elif n_bits < 32:
        secret_message = "OK"
    elif n_bits < 64:
        secret_message = "Segredo"
    else:
        secret_message = "Ataque"

    msg_int = text_to_int(secret_message)
    if msg_int >= n:
        secret_message = secret_message[:max(1, (n_bits // 8) - 1)]
        msg_int = text_to_int(secret_message)

    print(f"\n{'='*60}")
    print(f"  SIMULAÇÃO DE ATAQUE COMPLETO")
    print(f"{'='*60}")

    # Alice criptografa
    print(f"\n  [Alice] Criptografando mensagem secreta: \"{secret_message}\"")
    ciphertext = encrypt(msg_int, public_key)
    print(f"  [Alice] Mensagem cifrada: {ciphertext}")
    print(f"  [Alice] Envia o cifrado pela rede...")

    # Eve intercepta
    print(f"\n  [Eve - Atacante] Interceptou o cifrado: {ciphertext}")
    print(f"  [Eve - Atacante] Tem a chave pública (e={public_key[0]}, n={public_key[1]})")
    print(f"  [Eve - Atacante] Iniciando ataque por fatoração...")

    # Eve quebra a chave
    recovered_key = break_key(public_key)

    # Eve descriptografa
    print(f"\n  [Eve - Atacante] Usando chave privada recuperada para descriptografar...")
    recovered_int = decrypt(ciphertext, recovered_key)
    recovered_message = int_to_text(recovered_int)
    print(f"  [Eve - Atacante] Mensagem descriptografada: \"{recovered_message}\"")

    # Verifica
    original_d = original_private_key[0]
    recovered_d = recovered_key[0]

    print(f"\n{'─'*60}")
    print(f"  RESULTADO DO ATAQUE:")
    print(f"{'─'*60}")
    print(f"  Chave privada (d) original:   {original_d}")
    print(f"  Chave privada (d) recuperada: {recovered_d}")
    print(f"  Chaves idênticas: {'SIM - ataque bem-sucedido!' if original_d == recovered_d else 'NÃO'}")
    print(f"  Mensagem recuperada: \"{recovered_message}\" {'== original!' if recovered_message == secret_message else '!= original!'}")
    print(f"{'─'*60}")


# =============================================================================
# SEÇÃO 6: EXECUÇÃO PRINCIPAL
# =============================================================================


def run_lab(bits):
    """
    Executa todas as etapas do laboratório para um tamanho de chave.
    """
    print(f"\n{'#'*60}")
    print(f"#{'':^58}#")
    print(f"#{'LABORATÓRIO RSA - ' + str(bits * 2) + ' BITS':^58}#")
    print(f"#{'':^58}#")
    print(f"{'#'*60}")

    # Etapa 1: Gerar chaves
    public_key, private_key = generate_keys(bits)

    # Etapa 2: Criptografar e descriptografar
    demo_encryption(public_key, private_key)

    # Etapa 3: Formato PEM
    demo_pem_format(public_key, private_key)

    # Etapa 4: Quebrar a chave (somente para chaves pequenas)
    if bits <= 32:
        demo_full_attack(public_key, private_key)
    else:
        print(f"\n{'='*60}")
        print(f"  QUEBRA DA CHAVE - PULADA")
        print(f"{'='*60}")
        print(f"\n  Com {bits * 2} bits, a fatoração por divisão por tentativa")
        print(f"  poderia levar muito tempo. No mundo real (2048+ bits),")
        print(f"  isso é computacionalmente IMPOSSÍVEL com tecnologia atual.")
        print(f"\n  Estimativa para fatorar {bits * 2} bits por tentativa:")
        estimate = 2 ** (bits) / 1_000_000_000  # assumindo 1 bilhão de testes/s
        if estimate < 1:
            print(f"  ~{estimate*1000:.1f} milissegundos (ainda viável)")
        elif estimate < 60:
            print(f"  ~{estimate:.1f} segundos")
        elif estimate < 3600:
            print(f"  ~{estimate/60:.1f} minutos")
        elif estimate < 86400 * 365:
            print(f"  ~{estimate/3600:.1f} horas")
        else:
            print(f"  ~{estimate/(86400*365):.2e} anos (inviável!)")

    return public_key, private_key


def main():
    """
    Ponto de entrada do laboratório.

        Uso:
            python3 rsa_lab.py         -> executa com 16 bits (padrão do lab)
            python3 rsa_lab.py 16      -> chave de 16 bits (quebrável, didático)
            python3 rsa_lab.py 32      -> chave de 32 bits (quebrável, mais realista)
            python3 rsa_lab.py 64      -> chave de 64 bits (quebrável, segundos|minutos)
            python3 rsa_lab.py 512     -> chave de 512 bits (formato PEM real)
    """
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    LABORATÓRIO DE CRIPTOGRAFIA ASSIMÉTRICA RSA               ║
║                                                              ║
║    Este script implementa o RSA do zero para fins didáticos. ║
║    Cada etapa é documentada e explicada em detalhe.          ║
║                                                              ║
║    Etapas:                                                   ║
║      1. Geração de chaves (pública e privada)                ║
║      2. Criptografia e descriptografia de mensagens          ║
║      3. Exportação em formato PEM (ASN.1/DER + Base64)       ║
║      4. Quebra da chave por fatoração (ataque)               ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")

    # Processa argumento de linha de comando
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
    else:
        arg = "16"

    try:
        total_bits = int(arg)
        if total_bits < 8:
            print("  [!] Mínimo: 8 bits")
            total_bits = 8
        prime_bits = total_bits // 2
        run_lab(prime_bits)
    except ValueError:
        print(f"  [!] Argumento inválido: '{arg}'")
        print(f"  Uso: python3 rsa_lab.py [8|16|32|64|128|256|512|1024]")
        sys.exit(1)

    # Resumo final
    print(f"\n{'#'*60}")
    print(f"#{'':^58}#")
    print(f"#{'RESUMO DO LABORATÓRIO':^58}#")
    print(f"#{'':^58}#")
    print(f"{'#'*60}")
    print(f"""
  O que aprendemos:

  1. GERAÇÃO DE CHAVES
     - Dois primos aleatórios p e q geram o módulo n = p * q
     - phi(n) = (p-1)*(q-1) permite calcular a chave privada
     - Chave pública (e, n): criptografa
     - Chave privada (d, n): descriptografa

  2. CRIPTOGRAFIA/DESCRIPTOGRAFIA
     - Criptografar: ciphertext = message^e mod n
     - Descriptografar: message = ciphertext^d mod n
     - Funciona pelo Teorema de Euler: e*d ≡ 1 (mod phi(n))

  3. FORMATO PEM
     - As chaves são números inteiros, não "strings aleatórias"
     - O formato PEM é: números -> ASN.1 -> DER (binário) -> Base64 (texto)
     - Ferramentas como OpenSSL e SSH usam este formato

  4. QUEBRA POR FATORAÇÃO
     - Quem tem a chave pública tem n = p * q
     - Se conseguir fatorar n em p e q, reconstrói a chave privada
     - Com primos pequenos: instantâneo
     - Com primos de 1024+ bits: computacionalmente impossível

  5. POR QUE O RSA É SEGURO
     - Multiplicar dois primos: O(1) — instantâneo
     - Fatorar o resultado: O(2^(bits/2)) — exponencial
     - Essa assimetria é a base de toda a segurança
""")


if __name__ == "__main__":
    main()

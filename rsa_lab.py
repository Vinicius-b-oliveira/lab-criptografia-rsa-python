#!/usr/bin/env python3
"""Laboratorio RSA: explicacoes detalhadas no README."""

import base64
import math
import secrets
import sys
import time


def gcd(a, b):
    """Calcula o MDC usando Euclides."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """Retorna (g, x, y) tal que ax + by = g = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(e, phi):
    """Retorna d tal que (e * d) % phi == 1."""
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError(f"Inverso modular nao existe: gcd({e}, {phi}) = {g}")
    return x % phi


def is_prime_miller_rabin(n, rounds=20):
    """Teste probabilistico de primalidade."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    if n < 2000:
        for i in range(3, int(math.isqrt(n)) + 1, 2):
            if n % i == 0:
                return False
        return True

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits):
    """Gera um primo aleatorio com o numero de bits informado."""
    while True:
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1))
        n |= 1
        if is_prime_miller_rabin(n):
            return n


def generate_keys(bits):
    """Gera chaves RSA; bits representa o tamanho de cada primo."""
    print(f"\n[ETAPA 1] Gerando chaves RSA (~{bits * 2} bits)")

    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537
    if e >= phi_n:
        for candidate in (257, 17, 5, 3):
            if candidate < phi_n and gcd(candidate, phi_n) == 1:
                e = candidate
                break

    d = mod_inverse(e, phi_n)

    print(f"  n (modulo) ..........: {n}")
    print(f"  tamanho de n ........: {n.bit_length()} bits")
    print(f"  e (publico) .........: {e}")
    print(f"  d (privado) .........: {d}")
    print(f"  chave publica tupla .: {(e, n)}")
    print(f"  chave privada tupla .: {(d, n, p, q, e)}")
    if bits <= 16:
        print(f"  p e q (didatico) ....: {p}, {q}")

    return (e, n), (d, n, p, q, e)


def encrypt(message_int, public_key):
    """Criptografa um inteiro com chave publica."""
    e, n = public_key
    if message_int >= n:
        raise ValueError(
            f"Mensagem ({message_int}) deve ser menor que n ({n}). "
            "Use chave maior ou divida em blocos."
        )
    return pow(message_int, e, n)


def decrypt(ciphertext, private_key):
    """Descriptografa um inteiro com chave privada."""
    d, n = private_key[0], private_key[1]
    return pow(ciphertext, d, n)


def text_to_int(text):
    return int.from_bytes(text.encode("utf-8"), byteorder="big")


def int_to_text(number):
    byte_length = max(1, (number.bit_length() + 7) // 8)
    data = number.to_bytes(byte_length, byteorder="big")
    return data.decode("utf-8")


def demo_encryption(public_key, private_key, message=None):
    """Demonstra ciclo texto -> cifra -> texto."""
    _, n = public_key
    n_bits = n.bit_length()

    if message is None:
        if n_bits < 16:
            message = "A"
        elif n_bits < 32:
            message = "Hi"
        elif n_bits < 64:
            message = "RSA!"
        elif n_bits < 256:
            message = "Seguranca!"
        else:
            message = "RSA e incrivel"

    msg_int = text_to_int(message)
    if msg_int >= n:
        message = message[: max(1, (n_bits // 8) - 1)]
        msg_int = text_to_int(message)

    print("\n[ETAPA 2] Criptografia e descriptografia")
    print(f"  mensagem ............: {message}")
    print(f"  inteiro .............: {msg_int}")

    ciphertext = encrypt(msg_int, public_key)
    recovered_int = decrypt(ciphertext, private_key)
    recovered_text = int_to_text(recovered_int)

    print(f"  cifrado .............: {ciphertext}")
    print(f"  recuperado ..........: {recovered_text}")
    print(f"  status ..............: {'OK' if recovered_text == message else 'FALHA'}")

    return recovered_text == message, message


def encode_der_length(length):
    if length < 0x80:
        return bytes([length])
    byte_count = (length.bit_length() + 7) // 8
    return bytes([0x80 | byte_count]) + length.to_bytes(byte_count, "big")


def int_to_der(value):
    if value == 0:
        content = b"\x00"
    else:
        byte_length = (value.bit_length() + 7) // 8
        content = value.to_bytes(byte_length, "big")
        if content[0] & 0x80:
            content = b"\x00" + content
    return b"\x02" + encode_der_length(len(content)) + content


def der_sequence(content):
    return b"\x30" + encode_der_length(len(content)) + content


def private_key_to_pem(private_key):
    d, n, p, q, e = private_key
    exp1 = d % (p - 1)
    exp2 = d % (q - 1)
    coeff = mod_inverse(q, p)

    content = b"".join(
        [
            int_to_der(0),
            int_to_der(n),
            int_to_der(e),
            int_to_der(d),
            int_to_der(p),
            int_to_der(q),
            int_to_der(exp1),
            int_to_der(exp2),
            int_to_der(coeff),
        ]
    )

    der = der_sequence(content)
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]

    pem = "-----BEGIN RSA PRIVATE KEY-----\n"
    pem += "\n".join(lines) + "\n"
    pem += "-----END RSA PRIVATE KEY-----\n"
    return pem


def public_key_to_pem(public_key):
    e, n = public_key
    content = int_to_der(n) + int_to_der(e)
    der = der_sequence(content)

    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]

    pem = "-----BEGIN RSA PUBLIC KEY-----\n"
    pem += "\n".join(lines) + "\n"
    pem += "-----END RSA PUBLIC KEY-----\n"
    return pem


def demo_pem_format(public_key, private_key):
    """Mostra um resumo objetivo da exportacao PEM."""
    print("\n[ETAPA 3] Exportacao PEM (PKCS#1)")

    pem_pub = public_key_to_pem(public_key)
    pem_priv = private_key_to_pem(private_key)

    pub_lines = pem_pub.strip().split("\n")
    priv_lines = pem_priv.strip().split("\n")

    print(f"  chave publica ........: {len(pub_lines)} linhas PEM")
    print(f"  chave privada ........: {len(priv_lines)} linhas PEM")
    print(f"  cabecalho publica ....: {pub_lines[0]}")
    print(f"  cabecalho privada ....: {priv_lines[0]}")
    print("\n  chave publica PEM ....:")
    print(pem_pub.rstrip())
    print("\n  chave privada PEM ....:")
    print(pem_priv.rstrip())

    return pem_pub, pem_priv


def factorize(n):
    """Fatora n por divisao por tentativa."""
    if n % 2 == 0:
        return 2, n // 2, 1

    limit = math.isqrt(n) + 1
    attempts = 0
    if limit % 2 == 0:
        limit -= 1
    for i in range(limit, 3, -2):
        attempts += 1
        if n % i == 0:
            return i, n // i, attempts

    return n, 1, attempts


def break_key(public_key):
    """Recupera chave privada a partir da chave publica via fatoracao."""
    e, n = public_key

    print("\n[ETAPA 4] Ataque por fatoracao")
    print(f"  alvo n ...............: {n} ({n.bit_length()} bits)")

    start = time.time()
    p, q, attempts = factorize(n)
    elapsed = time.time() - start

    phi_n = (p - 1) * (q - 1)
    d = mod_inverse(e, phi_n)

    print(f"  fatores encontrados ..: p={p}, q={q}")
    print(f"  tentativas ...........: {attempts}")
    print(f"  tempo ................: {elapsed:.6f} s")
    print(f"  d recuperado .........: {d}")

    return d, n, p, q, e


def demo_full_attack(public_key, original_private_key, secret_message=None):
    """Simula interceptacao, quebra da chave e leitura da mensagem."""
    _, n = public_key
    n_bits = n.bit_length()

    if secret_message is None:
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
        secret_message = secret_message[: max(1, (n_bits // 8) - 1)]
        msg_int = text_to_int(secret_message)

    ciphertext = encrypt(msg_int, public_key)
    recovered_key = break_key(public_key)
    recovered_text = int_to_text(decrypt(ciphertext, recovered_key))

    print(f"  chave privada recup ..: {recovered_key}")
    print("  mensagem interceptada :", ciphertext)
    print("  mensagem recuperada ..:", recovered_text)
    print(
        "  status ataque ........:",
        "OK" if recovered_key[0] == original_private_key[0] else "FALHA",
    )


def run_lab(prime_bits):
    """Executa as etapas principais para um tamanho de primo."""
    total_bits = prime_bits * 2
    print("\n" + "=" * 58)
    print(f"LABORATORIO RSA - {total_bits} bits")
    print("=" * 58)

    public_key, private_key = generate_keys(prime_bits)
    _, etapa2_message = demo_encryption(public_key, private_key)
    demo_pem_format(public_key, private_key)

    if prime_bits <= 32:
        demo_full_attack(public_key, private_key, etapa2_message)
    else:
        estimate = 2 ** prime_bits / 1_000_000_000
        print("\n[ETAPA 4] Ataque por fatoracao")
        print("  pulado para evitar execucao longa.")
        if estimate < 1:
            eta = f"{estimate * 1000:.1f} ms"
        elif estimate < 60:
            eta = f"{estimate:.1f} s"
        elif estimate < 3600:
            eta = f"{estimate / 60:.1f} min"
        elif estimate < 86400 * 365:
            eta = f"{estimate / 3600:.1f} h"
        else:
            eta = f"{estimate / (86400 * 365):.2e} anos"
        print(f"  estimativa (trial div): {eta}")


def main():
    """Ponto de entrada.

    Uso:
      python3 rsa_lab.py         -> 16 bits (padrao)
      python3 rsa_lab.py 16      -> 16 bits
      python3 rsa_lab.py 32      -> 32 bits
      python3 rsa_lab.py 64      -> 64 bits (pode levar ~minutos no ataque)
      python3 rsa_lab.py 512     -> 512 bits
      python3 rsa_lab.py 1024    -> 1024 bits
    """
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
    else:
        arg = "16"

    try:
        total_bits = int(arg)
        if total_bits < 8:
            print("[!] Minimo: 8 bits")
            total_bits = 8

        run_lab(total_bits // 2)

    except ValueError:
        print(f"[!] Argumento invalido: '{arg}'")
        print("    Uso: python3 rsa_lab.py [8|16|32|64|128|256|512|1024]")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Nucleo reutilizavel para o laboratorio RSA."""

import ast
import base64
import math
import os
import secrets

pasta_bruteforce = "brute_force/public_message.py"


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(e, phi):
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError(f"Inverso modular nao existe: gcd({e}, {phi}) = {g}")
    return x % phi


def is_prime_miller_rabin(n, rounds=20):
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
    while True:
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1))
        n |= 1
        if is_prime_miller_rabin(n):
            return n


def generate_keys(prime_bits):
    p = generate_prime(prime_bits)
    q = generate_prime(prime_bits)
    while q == p:
        q = generate_prime(prime_bits)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537
    if e >= phi_n:
        for candidate in (257, 17, 5, 3):
            if candidate < phi_n and gcd(candidate, phi_n) == 1:
                e = candidate
                break

    d = mod_inverse(e, phi_n)
    return (e, n), (d, n, p, q, e)


def encrypt(message_int, public_key):
    e, n = public_key
    if message_int >= n:
        raise ValueError(
            f"Mensagem ({message_int}) deve ser menor que n ({n}). "
            "Use chave maior ou divida em blocos."
        )
    with open(pasta_bruteforce, "w") as arquivo:
        arquivo.write(f"class public_message:\n\tpublic_key = {public_key}")
    return pow(message_int, e, n)


def decrypt(ciphertext, private_key):
    d, n = private_key[0], private_key[1]
    with open(pasta_bruteforce, "a") as arquivo:
        arquivo.write(f"\n\tencrypted_message = {ciphertext}")
    return pow(ciphertext, d, n)


def text_to_int(text):
    return int.from_bytes(text.encode("utf-8"), byteorder="big")


def int_to_text(number):
    byte_length = max(1, (number.bit_length() + 7) // 8)
    data = number.to_bytes(byte_length, byteorder="big")
    return data.decode("utf-8")


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


def factorize(n):
    if n % 2 == 0:
        return 2, n // 2, 1

    limit = math.isqrt(n) + 1
    if limit % 2 == 0:
        limit -= 1
    attempts = 0
    for i in range(limit, 3, -2):
        attempts += 1
        if n % i == 0:
            return i, n // i, attempts

    return n, 1, attempts


def break_key(public_key):
    e, n = public_key
    p, q, attempts = factorize(n)
    phi_n = (p - 1) * (q - 1)
    d = mod_inverse(e, phi_n)
    return (d, n, p, q, e), attempts


def parse_key_tuple(text):
    value = ast.literal_eval(text)
    if not isinstance(value, tuple):
        raise ValueError("A chave deve estar em formato de tupla.")
    return value


def parse_public_key(text):
    key = parse_key_tuple(text)
    if len(key) != 2:
        raise ValueError("Chave publica deve ser (e, n).")
    return key


def parse_private_key(text):
    key = parse_key_tuple(text)
    if len(key) == 2:
        d, n = key
        return (d, n, None, None, None)
    if len(key) == 5:
        return key
    raise ValueError("Chave privada deve ser (d, n) ou (d, n, p, q, e).")


def _read_der_length(data, idx):
    first = data[idx]
    idx += 1
    if first < 0x80:
        return first, idx

    num_len_bytes = first & 0x7F
    if num_len_bytes == 0 or num_len_bytes > 4:
        raise ValueError("Length DER invalido.")

    length = int.from_bytes(data[idx : idx + num_len_bytes], "big")
    idx += num_len_bytes
    return length, idx


def _read_der_integer(data, idx):
    if data[idx] != 0x02:
        raise ValueError("Esperado INTEGER no DER.")
    idx += 1
    length, idx = _read_der_length(data, idx)
    raw = data[idx : idx + length]
    idx += length
    return int.from_bytes(raw, "big", signed=False), idx


def _read_der_sequence(data):
    idx = 0
    if data[idx] != 0x30:
        raise ValueError("Esperado SEQUENCE no DER.")
    idx += 1
    seq_len, idx = _read_der_length(data, idx)
    end = idx + seq_len
    if end > len(data):
        raise ValueError("DER truncado.")

    values = []
    while idx < end:
        value, idx = _read_der_integer(data, idx)
        values.append(value)

    if idx != end:
        raise ValueError("DER invalido: bytes extras na SEQUENCE.")
    return values


def _extract_pem_content(text, begin_line, end_line):
    stripped = text.strip()
    if begin_line not in stripped or end_line not in stripped:
        raise ValueError("Bloco PEM invalido.")

    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    try:
        start = lines.index(begin_line)
        finish = lines.index(end_line)
    except ValueError as exc:
        raise ValueError("Cabecalho/rodape PEM ausente.") from exc

    if finish <= start + 1:
        raise ValueError("PEM sem conteudo Base64.")

    b64_data = "".join(lines[start + 1 : finish])
    return base64.b64decode(b64_data)


def parse_public_key_pem(text):
    der = _extract_pem_content(
        text,
        "-----BEGIN RSA PUBLIC KEY-----",
        "-----END RSA PUBLIC KEY-----",
    )
    values = _read_der_sequence(der)
    if len(values) != 2:
        raise ValueError("Chave publica PEM invalida.")
    n, e = values
    return (e, n)


def parse_private_key_pem(text):
    der = _extract_pem_content(
        text,
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
    )
    values = _read_der_sequence(der)
    if len(values) < 6:
        raise ValueError("Chave privada PEM invalida.")

    _version = values[0]
    n = values[1]
    e = values[2]
    d = values[3]
    p = values[4]
    q = values[5]
    return (d, n, p, q, e)


def resolve_key_input(key_input):
    if os.path.exists(key_input):
        with open(key_input, "r", encoding="utf-8") as file:
            return file.read().strip()
    return key_input.strip()


def parse_public_key_input(key_input):
    text = resolve_key_input(key_input)
    if "BEGIN RSA PUBLIC KEY" in text:
        return parse_public_key_pem(text)
    return parse_public_key(text)


def parse_private_key_input(key_input):
    text = resolve_key_input(key_input)
    if "BEGIN RSA PRIVATE KEY" in text:
        return parse_private_key_pem(text)
    return parse_private_key(text)


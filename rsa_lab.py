#!/usr/bin/env python3
"""Laboratorio RSA: explicacoes detalhadas no README."""

import sys
import time

from rsa_core import (
    block_size,
    break_key,
    decrypt,
    decrypt_text,
    encrypt,
    encrypt_text,
    generate_keys,
    int_to_text,
    private_key_to_pem,
    public_key_to_pem,
    text_to_int,
)


def demo_generate_keys(prime_bits):
    print(f"\n[ETAPA 1] Gerando chaves RSA (~{prime_bits * 2} bits)")
    public_key, private_key = generate_keys(prime_bits)

    d, n, p, q, e = private_key
    print(f"  n (modulo) ..........: {n}")
    print(f"  tamanho de n ........: {n.bit_length()} bits")
    print(f"  e (publico) .........: {e}")
    print(f"  d (privado) .........: {d}")
    print(f"  chave publica tupla .: {public_key}")
    print(f"  chave privada tupla .: {private_key}")
    if prime_bits <= 16:
        print(f"  p e q (didatico) ....: {p}, {q}")

    return public_key, private_key


def demo_encryption(public_key, private_key):
    _, n = public_key
    n_bits = n.bit_length()
    bs = block_size(public_key)

    if n_bits < 16:
        short_msg = "A"
    elif n_bits < 32:
        short_msg = "Hi"
    elif n_bits < 64:
        short_msg = "RSA!"
    else:
        short_msg = "Seguranca!"

    short_msg = short_msg[:bs] if len(short_msg.encode("utf-8")) > bs else short_msg
    msg_int = text_to_int(short_msg)

    print("\n[ETAPA 2a] Criptografia classica (1 bloco)")
    print(f"  mensagem ............: {short_msg}")
    print(f"  inteiro .............: {msg_int}")

    ciphertext = encrypt(msg_int, public_key)
    recovered_int = decrypt(ciphertext, private_key)
    recovered_text = int_to_text(recovered_int)

    print(f"  cifrado .............: {ciphertext}")
    print(f"  recuperado ..........: {recovered_text}")
    print(f"  status ..............: {'OK' if recovered_text == short_msg else 'FALHA'}")

    long_msg = "RSA com blocos funciona para mensagens grandes!"
    if len(long_msg.encode("utf-8")) <= bs:
        long_msg = long_msg * ((bs // len(long_msg.encode("utf-8"))) + 2)

    blocks = encrypt_text(long_msg, public_key)
    recovered_long = decrypt_text(blocks, private_key)

    print(f"\n[ETAPA 2b] Criptografia por blocos (mensagem maior que n)")
    print(f"  mensagem ............: {long_msg}")
    print(f"  bytes da mensagem ...: {len(long_msg.encode('utf-8'))}")
    print(f"  tamanho do bloco ....: {bs} bytes")
    print(f"  blocos cifrados .....: {len(blocks)}")
    for i, b in enumerate(blocks):
        print(f"    bloco {i + 1} ............: {b}")
    print(f"  recuperado ..........: {recovered_long}")
    print(f"  status ..............: {'OK' if recovered_long == long_msg else 'FALHA'}")

    return recovered_long == long_msg


def demo_pem_format(public_key, private_key):
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


def demo_full_attack(public_key, original_private_key):
    _, n = public_key
    bs = block_size(public_key)

    secret_message = "Ataque"
    if len(secret_message.encode("utf-8")) > bs:
        secret_message = secret_message[:bs]

    msg_int = text_to_int(secret_message)
    ciphertext = encrypt(msg_int, public_key)

    print("\n[ETAPA 4] Ataque por fatoracao")
    print(f"  alvo n ...............: {n} ({n.bit_length()} bits)")

    start = time.time()
    recovered_key, attempts = break_key(public_key)
    elapsed = time.time() - start

    recovered_text = int_to_text(decrypt(ciphertext, recovered_key))

    print(f"  fatores encontrados ..: p={recovered_key[2]}, q={recovered_key[3]}")
    print(f"  tentativas ...........: {attempts}")
    print(f"  tempo ................: {elapsed:.6f} s")
    print(f"  d recuperado .........: {recovered_key[0]}")
    print(f"  chave privada recup ..: {recovered_key}")
    print("  mensagem interceptada :", ciphertext)
    print("  mensagem recuperada ..:", recovered_text)
    print(
        "  status ataque ........:",
        "OK" if recovered_key[0] == original_private_key[0] else "FALHA",
    )


def run_lab(prime_bits):
    total_bits = prime_bits * 2
    print("\n" + "=" * 58)
    print(f"LABORATORIO RSA - {total_bits} bits")
    print("=" * 58)

    public_key, private_key = demo_generate_keys(prime_bits)
    demo_encryption(public_key, private_key)
    demo_pem_format(public_key, private_key)

    if prime_bits <= 32:
        demo_full_attack(public_key, private_key)
    else:
        estimate = 2**prime_bits / 1_000_000_000
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

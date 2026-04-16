#!/usr/bin/env python3
"""CLI para descriptografar com chave privada RSA."""

import sys

from rsa_core import decrypt_text, parse_private_key_input


def main():
    if len(sys.argv) >= 3:
        key_text = sys.argv[1]
        ciphertext_text = sys.argv[2]
    else:
        key_text = input("Chave privada (tupla, PEM ou arquivo .pem): ").strip()
        ciphertext_text = input("Ciphertext (inteiros separados por virgula): ").strip()

    try:
        private_key = parse_private_key_input(key_text)
        blocks = [int(b.strip()) for b in ciphertext_text.split(",")]
        recovered_text = decrypt_text(blocks, private_key)
    except Exception as exc:
        print(f"[!] Erro: {exc}")
        print(
            "    Uso: python3 rsa_decrypt.py '<(d,n)|PEM|arquivo.pem>' '<cifrado1,cifrado2,...>'"
        )
        sys.exit(1)

    print("[DECRYPT] Resultado")
    print(f"  blocos recebidos ....: {len(blocks)}")
    print(f"  texto recuperado ....: {recovered_text}")


if __name__ == "__main__":
    main()

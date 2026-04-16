#!/usr/bin/env python3
"""CLI para descriptografar com chave privada RSA."""

import argparse
import sys

from rsa_core import decrypt_text, parse_private_key_input, raw_to_blocks


def build_parser():
    parser = argparse.ArgumentParser(
        description="Descriptografa mensagem com chave privada RSA.",
    )
    parser.add_argument(
        "key",
        nargs="?",
        help="Chave privada: tupla (d, n), texto PEM ou caminho .pem",
    )
    parser.add_argument(
        "ciphertext",
        nargs="?",
        help="Texto cifrado (inteiros separados por virgula, ou Base64 com --raw)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Entrada em formato raw (Base64 de blocos binarios concatenados).",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.key and args.ciphertext:
        key_text = args.key
        ciphertext_text = args.ciphertext
    else:
        key_text = input("Chave privada (tupla, PEM ou arquivo .pem): ").strip()
        if args.raw:
            ciphertext_text = input("Ciphertext (Base64): ").strip()
        else:
            ciphertext_text = input("Ciphertext (inteiros separados por virgula): ").strip()

    try:
        private_key = parse_private_key_input(key_text)

        if args.raw:
            public_key = (private_key[4], private_key[1])
            blocks = raw_to_blocks(ciphertext_text, public_key)
        else:
            blocks = [int(b.strip()) for b in ciphertext_text.split(",")]

        recovered_text = decrypt_text(blocks, private_key)
    except Exception as exc:
        print(f"[!] Erro: {exc}")
        print(
            "    Uso: python3 rsa_decrypt.py [--raw] '<(d,n)|PEM|arquivo.pem>' '<cifrado>'"
        )
        sys.exit(1)

    print("[DECRYPT] Resultado")
    print(f"  formato .............: {'raw (Base64)' if args.raw else 'didatico (inteiros)'}")
    print(f"  blocos recebidos ....: {len(blocks)}")
    print(f"  texto recuperado ....: {recovered_text}")


if __name__ == "__main__":
    main()

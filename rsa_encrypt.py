#!/usr/bin/env python3
"""CLI para criptografar mensagem com chave publica RSA."""

import argparse
import sys

from rsa_core import block_size, blocks_to_raw, encrypt_text, parse_public_key_input


def build_parser():
    parser = argparse.ArgumentParser(
        description="Criptografa mensagem com chave publica RSA.",
    )
    parser.add_argument(
        "key",
        nargs="?",
        help="Chave publica: tupla (e, n), texto PEM ou caminho .pem",
    )
    parser.add_argument(
        "message",
        nargs="*",
        help="Mensagem a criptografar",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Saida realista: blocos binarios concatenados em Base64.",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.key and args.message:
        key_text = args.key
        message = " ".join(args.message)
    else:
        key_text = input("Chave publica (tupla, PEM ou arquivo .pem): ").strip()
        message = input("Mensagem: ").strip()

    try:
        public_key = parse_public_key_input(key_text)
        blocks = encrypt_text(message, public_key)
    except Exception as exc:
        print(f"[!] Erro: {exc}")
        print("    Uso: python3 rsa_encrypt.py [--raw] '<(e,n)|PEM|arquivo.pem>' 'mensagem'")
        sys.exit(1)

    print("[ENCRYPT] Resultado")
    print(f"  mensagem ............: {message}")
    print(f"  tamanho do bloco ....: {block_size(public_key)} bytes")
    print(f"  blocos cifrados .....: {len(blocks)}")

    if args.raw:
        raw = blocks_to_raw(blocks, public_key)
        print(f"  formato .............: raw (Base64)")
        print(f"  cifrado .............:\n{raw}")
    else:
        serialized = ",".join(str(b) for b in blocks)
        print(f"  formato .............: didatico (inteiros)")
        print(f"  cifrado .............: {serialized}")


if __name__ == "__main__":
    main()

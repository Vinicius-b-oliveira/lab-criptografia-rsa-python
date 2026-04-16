#!/usr/bin/env python3
"""CLI para geracao de chaves RSA."""

import argparse
from datetime import datetime
from pathlib import Path
import sys

from rsa_core import generate_keys, private_key_to_pem, public_key_to_pem

pasta_bruteforce = "brute_force/public_message.py"

def build_parser():
    parser = argparse.ArgumentParser(
        description="Gera chaves RSA em tupla e/ou PEM.",
    )
    parser.add_argument(
        "bits",
        nargs="?",
        default=16,
        type=int,
        help="Tamanho total da chave em bits (ex.: 16, 32, 64, 512)",
    )
    parser.add_argument(
        "--output",
        choices=["terminal", "file", "both"],
        default="terminal",
        help="Define onde exibir/salvar as chaves.",
    )
    parser.add_argument(
        "--out-dir",
        default="keys",
        help="Diretorio para salvar arquivos PEM quando output=file|both.",
    )
    return parser


def save_pem_files(public_pem, private_pem, total_bits, out_dir):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    public_path = Path(out_dir) / f"rsa_{total_bits}_public_{stamp}.pem"
    private_path = Path(out_dir) / f"rsa_{total_bits}_private_{stamp}.pem"

    public_path.write_text(public_pem, encoding="utf-8")
    private_path.write_text(private_pem, encoding="utf-8")
    return str(public_path), str(private_path)


def main():
    parser = build_parser()
    args = parser.parse_args()

    total_bits = args.bits
    if total_bits < 8:
        print("[!] Minimo: 8 bits")
        total_bits = 8

    public_key, private_key = generate_keys(total_bits // 2)
    with open(pasta_bruteforce, "w") as arquivo:
        arquivo.write(f"class public_message:\n\tpublic_key = {public_key}\n\tencrypted_message = ''")
    public_pem = public_key_to_pem(public_key)
    private_pem = private_key_to_pem(private_key)

    print(f"\n[KEYGEN] Chaves RSA (~{total_bits} bits)")
    print(f"  chave publica tupla .: {public_key}")
    print(f"  chave privada tupla .: {private_key}")

    if args.output in ("terminal", "both"):
        print("\n  chave publica PEM ....:")
        print(public_pem.rstrip())
        print("\n  chave privada PEM ....:")
        print(private_pem.rstrip())

    if args.output in ("file", "both"):
        public_path, private_path = save_pem_files(
            public_pem,
            private_pem,
            total_bits,
            args.out_dir,
        )
        print("\n  arquivos PEM salvos ..:")
        print(f"  publico ..............: {public_path}")
        print(f"  privado ..............: {private_path}")


if __name__ == "__main__":
    main()

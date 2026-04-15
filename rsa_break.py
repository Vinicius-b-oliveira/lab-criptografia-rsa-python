#!/usr/bin/env python3
"""CLI para quebra didatica de chave RSA por fatoracao."""

import sys
import time

from rsa_core import break_key, parse_public_key_input


def main():
    if len(sys.argv) >= 2:
        key_text = sys.argv[1]
    else:
        key_text = input("Chave publica (tupla, PEM ou arquivo .pem): ").strip()

    try:
        public_key = parse_public_key_input(key_text)
    except Exception as exc:
        print(f"[!] Erro: {exc}")
        print("    Uso: python3 rsa_break.py '<(e,n)|PEM|arquivo.pem>'")
        sys.exit(1)

    print("[BREAK] Ataque por fatoracao")
    print(f"  chave publica .......: {public_key}")

    start = time.time()
    recovered_key, attempts = break_key(public_key)
    elapsed = time.time() - start

    print(f"  chave privada recup ..: {recovered_key}")
    print(f"  tentativas ...........: {attempts}")
    print(f"  tempo ................: {elapsed:.6f} s")


if __name__ == "__main__":
    main()

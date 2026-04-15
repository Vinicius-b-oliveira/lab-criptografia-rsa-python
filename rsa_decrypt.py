#!/usr/bin/env python3
"""CLI para descriptografar com chave privada RSA."""

import sys

from rsa_core import decrypt, int_to_text, parse_private_key_input


def main():
    if len(sys.argv) >= 3:
        key_text = sys.argv[1]
        ciphertext_text = sys.argv[2]
    else:
        key_text = input("Chave privada (tupla, PEM ou arquivo .pem): ").strip()
        ciphertext_text = input("Ciphertext (inteiro): ").strip()

    try:
        private_key = parse_private_key_input(key_text)
        ciphertext = int(ciphertext_text)
        recovered_int = decrypt(ciphertext, private_key)
        recovered_text = int_to_text(recovered_int)
    except Exception as exc:
        print(f"[!] Erro: {exc}")
        print("    Uso: python3 rsa_decrypt.py '<(d,n)|PEM|arquivo.pem>' '<ciphertext>'")
        sys.exit(1)

    print("[DECRYPT] Resultado")
    print(f"  ciphertext ..........: {ciphertext}")
    print(f"  inteiro recuperado ..: {recovered_int}")
    print(f"  texto recuperado ....: {recovered_text}")


if __name__ == "__main__":
    main()

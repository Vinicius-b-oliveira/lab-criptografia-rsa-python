#!/usr/bin/env python3
"""CLI para criptografar mensagem com chave publica RSA."""

import sys

from rsa_core import encrypt, parse_public_key_input, text_to_int


def main():
    if len(sys.argv) >= 3:
        key_text = sys.argv[1]
        message = " ".join(sys.argv[2:])
    else:
        key_text = input("Chave publica (tupla, PEM ou arquivo .pem): ").strip()
        message = input("Mensagem: ").strip()

    try:
        public_key = parse_public_key_input(key_text)
        message_int = text_to_int(message)
        ciphertext = encrypt(message_int, public_key)
    except Exception as exc:
        print(f"[!] Erro: {exc}")
        print("    Uso: python3 rsa_encrypt.py '<(e, n)|PEM|arquivo.pem>' 'mensagem'")
        sys.exit(1)

    print("[ENCRYPT] Resultado")
    print(f"  mensagem ............: {message}")
    print(f"  inteiro .............: {message_int}")
    print(f"  cifrado .............: {ciphertext}")


if __name__ == "__main__":
    main()

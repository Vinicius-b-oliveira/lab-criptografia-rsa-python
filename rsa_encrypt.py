#!/usr/bin/env python3
"""CLI para criptografar mensagem com chave publica RSA."""

import sys

from rsa_core import block_size, encrypt_text, parse_public_key_input


def main():
    if len(sys.argv) >= 3:
        key_text = sys.argv[1]
        message = " ".join(sys.argv[2:])
    else:
        key_text = input("Chave publica (tupla, PEM ou arquivo .pem): ").strip()
        message = input("Mensagem: ").strip()

    try:
        public_key = parse_public_key_input(key_text)
        blocks = encrypt_text(message, public_key)
    except Exception as exc:
        print(f"[!] Erro: {exc}")
        print("    Uso: python3 rsa_encrypt.py '<(e, n)|PEM|arquivo.pem>' 'mensagem'")
        sys.exit(1)

    serialized = ",".join(str(b) for b in blocks)

    print("[ENCRYPT] Resultado")
    print(f"  mensagem ............: {message}")
    print(f"  tamanho do bloco ....: {block_size(public_key)} bytes")
    print(f"  blocos cifrados .....: {len(blocks)}")
    print(f"  cifrado .............: {serialized}")


if __name__ == "__main__":
    main()

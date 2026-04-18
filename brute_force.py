#!/usr/bin/env python3
"""CLI de quebra RSA focada em performance (Pollard Rho)."""

import sys
import math
import secrets
import time

from rsa_core import parse_public_key_input


def gcd(a, b):
    """Calcula o MDC usando Euclides."""
    while b:
        a, b = b, a % b
        return a


def extended_gcd(a, b):
    """Retorna (g, x, y) tal que ax + by = g = gcd(a, b)."""

    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(e, phi):
    """Retorna d tal que (e * d) % phi == 1."""

    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError(f"Inverso modular nao existe: gcd({e}, {phi}) = {g}")
    return x % phi


def factorize(n):
    x = 2
    y = 2
    d = 1
    c = 1
    attempts = 0
    while d == 1:
        attempts += 1
        x = (pow(x, 2, n) + c) % n

        y = (pow(y, 2, n) + c) % n
        y = (pow(y, 2, n) + c) % n

        d = math.gcd(abs(x - y), n)

        if d == n:
            x = secrets.randbelow(n - 3) + 2
            y = x
            c = secrets.randbelow(n - 1) + 1
            d = 1
    p = d
    q = n // p
    return p, q, attempts


def break_key(public_key):
    e, n = public_key

    start = time.time()
    p, q, attempts = factorize(n)
    end = time.time() - start

    phi_n = (p - 1) * (q - 1)

    d = mod_inverse(e, phi_n)

    return (d, n, p, q, e), attempts, end


def main():
    if len(sys.argv) >= 2:
        key_text = sys.argv[1]
    else:
        key_text = input("Chave publica (tupla, PEM ou arquivo .pem): ").strip()

    try:
        public_key = parse_public_key_input(key_text)
        recovered_key, _attempts, _elapsed = break_key(public_key)
    except Exception as exc:
        print(f"[!] Erro: {exc}")
        print("    Uso: python3 brute_force.py '<(e,n)|PEM|arquivo.pem>'")
        sys.exit(1)

    print(recovered_key)


if __name__ == "__main__":
    main()

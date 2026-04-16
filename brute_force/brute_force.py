from public_message import public_message 
import math 
import secrets 
import time 

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
            c = secrets.randbelow(n -1) + 1 
            d = 1 
    p = d 
    q = n // p 
    return p, q, attempts 
        
def break_key():
    e, n = public_message.public_key

    start = time.time()
    p, q, attempts = factorize(n)
    end = time.time() - start

    phi_n = (p - 1) * (q - 1)

    d = mod_inverse(e, phi_n)

    return d, n, attempts, end

def decrypt():
    d, n, attempts, end = break_key()
    message = public_message.encrypted_message

    return pow(message, d, n), attempts, end

def int_to_text(number):
    byte_length = max(1, (number.bit_length() + 7) // 8)
    data = number.to_bytes(byte_length, byteorder="big")
    
    return data.decode("utf-8")

if __name__ == '__main__': 
    byte_message, attempts, end = decrypt()
    message = int_to_text(byte_message)

    print(f"tentativas = {attempts}")
    print(f"tempo = {format(end, '.10f')}s")
    print(f"Mensagem = {message}")
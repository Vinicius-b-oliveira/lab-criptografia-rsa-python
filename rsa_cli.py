#!/usr/bin/env python3
"""CLI interativa com menus de selecao para o laboratorio RSA."""

import time

from simple_term_menu import TerminalMenu

from rsa_core import (
    block_size,
    blocks_to_raw,
    break_key,
    cipher_block_size,
    decrypt_text,
    encrypt_text,
    generate_keys,
    private_key_to_pem,
    public_key_to_pem,
    raw_to_blocks,
)

# -- Estado da sessao ----------------------------------------------------

state = {
    "public_key": None,
    "private_key": None,
    "prime_bits": None,
    "last_blocks": None,
    "last_raw": None,
}


# -- Helpers -------------------------------------------------------------


def header():
    print("\n========================================")
    print("  RSA Lab - CLI Interativa")
    print("========================================")


def show_status():
    if state["public_key"] is None:
        print("\n  Nenhuma chave gerada.")
        return
    _, n = state["public_key"]
    print(f"\n  chave ativa .........: {n.bit_length()} bits")
    print(f"  publica .............: {state['public_key']}")
    print(f"  bloco (texto claro) .: {block_size(state['public_key'])} bytes")
    print(f"  bloco (cifrado) .....: {cipher_block_size(state['public_key'])} bytes")
    if state["last_blocks"]:
        print(f"  ultimo cifrado ......: {len(state['last_blocks'])} blocos em memoria")


def require_keys():
    if state["public_key"] is None:
        print("\n  [!] Nenhuma chave gerada. Use 'Gerar chaves' primeiro.")
        return False
    return True


def pause():
    input("\n  [Enter para continuar]")


def select(title, options):
    print(f"\n  {title}")
    menu = TerminalMenu(
        options,
        menu_cursor_style=("fg_cyan", "bold"),
        menu_highlight_style=("fg_cyan", "bold"),
    )
    idx = menu.show()
    return idx


# -- Acoes ---------------------------------------------------------------


def action_generate():
    options = ["16 bits (didatico)", "32 bits (quebravel)", "64 bits", "128 bits", "256 bits", "512 bits", "1024 bits", "2048 bits"]
    idx = select("Tamanho da chave:", options)
    if idx is None:
        return

    bits_map = [16, 32, 64, 128, 256, 512, 1024, 2048]
    total_bits = bits_map[idx]

    state["prime_bits"] = total_bits // 2
    state["public_key"], state["private_key"] = generate_keys(state["prime_bits"])
    state["last_blocks"] = None
    state["last_raw"] = None

    d, n, p, q, e = state["private_key"]
    print(f"\n  Chaves geradas ({n.bit_length()} bits)")
    print(f"  n ...................: {n}")
    print(f"  e ...................: {e}")
    print(f"  d ...................: {d}")
    print(f"  publica .............: {state['public_key']}")
    print(f"  privada .............: {state['private_key']}")
    pause()


def action_encrypt():
    if not require_keys():
        pause()
        return

    message = input("\n  Mensagem: ").strip()
    if not message:
        print("  [!] Mensagem vazia.")
        return

    fmt_options = ["Didatico (inteiros separados por virgula)", "Raw (Base64 binario realista)"]
    fmt_idx = select("Formato de saida:", fmt_options)
    if fmt_idx is None:
        return

    raw_mode = fmt_idx == 1

    blocks = encrypt_text(message, state["public_key"])
    state["last_blocks"] = blocks

    bs = block_size(state["public_key"])
    print(f"\n  mensagem ............: {message}")
    print(f"  tamanho do bloco ....: {bs} bytes")
    print(f"  blocos cifrados .....: {len(blocks)}")

    if raw_mode:
        raw = blocks_to_raw(blocks, state["public_key"])
        state["last_raw"] = raw
        print(f"  formato .............: raw (Base64)")
        print(f"  cifrado .............:\n  {raw}")
    else:
        state["last_raw"] = None
        serialized = ",".join(str(b) for b in blocks)
        print(f"  formato .............: didatico (inteiros)")
        print(f"  cifrado .............: {serialized}")
    pause()


def action_decrypt():
    if not require_keys():
        pause()
        return

    src_options = ["Ultimo cifrado da sessao", "Informar cifrado manualmente"]
    src_idx = select("Origem do cifrado:", src_options)
    if src_idx is None:
        return

    if src_idx == 0:
        if state["last_blocks"] is None:
            print("\n  [!] Nenhum cifrado em memoria. Encripte algo antes.")
            pause()
            return
        blocks = state["last_blocks"]
        raw_mode = state["last_raw"] is not None
    else:
        fmt_options = ["Didatico (inteiros separados por virgula)", "Raw (Base64)"]
        fmt_idx = select("Formato do cifrado:", fmt_options)
        if fmt_idx is None:
            return
        raw_mode = fmt_idx == 1

        ciphertext_text = input("\n  Cifrado: ").strip()
        if not ciphertext_text:
            print("  [!] Entrada vazia.")
            return

        try:
            if raw_mode:
                public_key = (state["private_key"][4], state["private_key"][1])
                blocks = raw_to_blocks(ciphertext_text, public_key)
            else:
                blocks = [int(b.strip()) for b in ciphertext_text.split(",")]
        except Exception as exc:
            print(f"  [!] Erro ao interpretar cifrado: {exc}")
            pause()
            return

    recovered = decrypt_text(blocks, state["private_key"])

    fmt = "raw (Base64)" if raw_mode else "didatico (inteiros)"
    print(f"\n  formato .............: {fmt}")
    print(f"  blocos ..............: {len(blocks)}")
    print(f"  texto recuperado ....: {recovered}")
    pause()


def action_break():
    if not require_keys():
        pause()
        return

    _, n = state["public_key"]
    print(f"\n  alvo n ...............: {n} ({n.bit_length()} bits)")

    prime_bits = state["prime_bits"]
    if prime_bits and prime_bits > 32:
        estimate = 2**prime_bits / 1_000_000_000
        if estimate > 60:
            if estimate < 3600:
                eta = f"{estimate / 60:.1f} min"
            else:
                eta = f"{estimate / 3600:.1f} h"
            print(f"  [!] Estimativa de tempo: {eta}.")
            idx = select("Isso pode demorar. Continuar?", ["Sim", "Cancelar"])
            if idx != 0:
                print("  Cancelado.")
                pause()
                return

    print("  Fatorando...")
    start = time.time()
    recovered_key, attempts = break_key(state["public_key"])
    elapsed = time.time() - start

    print(f"  fatores ..............: p={recovered_key[2]}, q={recovered_key[3]}")
    print(f"  tentativas ...........: {attempts}")
    print(f"  tempo ................: {elapsed:.6f} s")
    print(f"  d recuperado .........: {recovered_key[0]}")
    print(
        "  status ...............: ",
        "OK" if recovered_key[0] == state["private_key"][0] else "FALHA",
    )
    pause()


def action_pem():
    if not require_keys():
        pause()
        return

    pem_pub = public_key_to_pem(state["public_key"])
    pem_priv = private_key_to_pem(state["private_key"])

    print("\n  Chave publica PEM:")
    print(pem_pub.rstrip())
    print("\n  Chave privada PEM:")
    print(pem_priv.rstrip())
    pause()


def action_status():
    show_status()
    pause()


# -- Menu principal ------------------------------------------------------


MENU_OPTIONS = [
    "Gerar chaves",
    "Encriptar mensagem",
    "Decriptar mensagem",
    "Quebrar chave (fatoracao)",
    "Exibir PEM",
    "Status da sessao",
    "Sair",
]

ACTIONS = [
    action_generate,
    action_encrypt,
    action_decrypt,
    action_break,
    action_pem,
    action_status,
]


def main():
    header()

    while True:
        print()
        menu = TerminalMenu(
            MENU_OPTIONS,
            title="  O que deseja fazer?",
            menu_cursor_style=("fg_cyan", "bold"),
            menu_highlight_style=("fg_cyan", "bold"),
        )
        idx = menu.show()

        if idx is None or idx == len(MENU_OPTIONS) - 1:
            print("\n  Ate mais!\n")
            break

        ACTIONS[idx]()


if __name__ == "__main__":
    main()

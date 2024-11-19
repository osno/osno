from Components.ActionMap import ActionMap
from os.path import exists
import ctypes

# Determina il nome della macchina corrente (esempio generico)
def get_current_machine():
    try:
        with open("/etc/hostname", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        raise RuntimeError("Impossibile determinare il nome della macchina")

# Funzione per verificare se una macchina è esclusa
def is_excluded(machine_name: str) -> bool:
    # Percorso statico alla libreria
    lib_path = "/usr/lib/libexclude_machine.so.0.0.0"

    if not exists(lib_path):
        raise FileNotFoundError(f"Libreria non trovata: {lib_path}")

    exclude_machine = ctypes.CDLL(lib_path)
    exclude_machine.is_machine_excluded.argtypes = [ctypes.c_char_p]
    exclude_machine.is_machine_excluded.restype = ctypes.c_int

    return exclude_machine.is_machine_excluded(machine_name.encode("utf-8")) != 0

# Statement principale
current_machine = get_current_machine()
if is_excluded(current_machine):
    print(f"La macchina {current_machine} è esclusa dall'avvio.")
else:
    print(f"La macchina {current_machine} è autorizzata.")

globalActionMap = ActionMap(["GlobalActions"])
globalActionMap.execBegin()

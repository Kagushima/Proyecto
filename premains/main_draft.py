import tkinter as tk
from tkinter import ttk, messagebox
import base64
from functions import AES as aes
from functions import Cesar as csr

# -------------------------
# Funciones auxiliares
# -------------------------

def cifrar_cesar():
    texto = entry_texto_cesar.get("1.0", tk.END).strip()
    try:
        desplazamiento = int(entry_clave_cesar.get())
    except ValueError:
        messagebox.showerror("Error", "El desplazamiento debe ser un número entero.")
        return

    if not texto:
        messagebox.showwarning("Aviso", "Ingrese un texto para cifrar.")
        return

    resultado = csr.cesar_encrypt(texto, desplazamiento)
    text_resultado_cesar.delete("1.0", tk.END)
    text_resultado_cesar.insert(tk.END, resultado)

def descifrar_cesar():
    texto = entry_texto_cesar.get("1.0", tk.END).strip()
    try:
        desplazamiento = int(entry_clave_cesar.get())
    except ValueError:
        messagebox.showerror("Error", "El desplazamiento debe ser un número entero.")
        return

    resultado = csr.cesar_decrypt(texto, desplazamiento)
    text_resultado_cesar.delete("1.0", tk.END)
    text_resultado_cesar.insert(tk.END, resultado)

# --- AES ---

def cifrar_aes():
    mensaje = entry_texto_aes.get("1.0", tk.END).strip()
    clave = entry_clave_aes.get().strip()

    if len(clave) != 16:
        messagebox.showerror("Error", "La clave debe tener exactamente 16 caracteres.")
        return
    if len(mensaje) != 16:
        messagebox.showerror("Error", "El mensaje debe tener exactamente 16 caracteres.")
        return

    # Reutilizamos funciones de AES.py
    state = []
    key0 = []
    for a in range(4):
        state.append([])
        key0.append([])
        for i in range(4):
            state[a].append(ord(mensaje[i + a * 4]))
            key0[a].append(ord(clave[i + a * 4]))

    for i in range(4):
        for j in range(4):
            state[i][j] ^= key0[i][j]

    round_keys = aes.key_generation(key0)
    for round in range(1, 10):
        aes.sub_bytes(state)
        aes.shift_rows(state)
        aes.mix_columns(state)
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_keys[round][i][j]
    aes.sub_bytes(state)
    aes.shift_rows(state)
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_keys[10][i][j]

    for i in range(4):
        for j in range(4):
            state[i][j] = chr(state[i][j])

    ciphertext = ''.join([''.join(row) for row in state])
    texto_cifrado_b64 = base64.b64encode(ciphertext.encode()).decode()

    text_resultado_aes.delete("1.0", tk.END)
    text_resultado_aes.insert(tk.END, texto_cifrado_b64)

def descifrar_aes():
    mensaje_cifrado_b64 = entry_texto_aes.get("1.0", tk.END).strip()
    clave = entry_clave_aes.get().strip()

    if len(clave) != 16:
        messagebox.showerror("Error", "La clave debe tener exactamente 16 caracteres.")
        return

    try:
        ciphertext = base64.b64decode(mensaje_cifrado_b64).decode()
    except Exception:
        messagebox.showerror("Error", "Texto cifrado no es válido o no está en Base64.")
        return

    state = []
    key0 = []
    for a in range(4):
        state.append([])
        key0.append([])
        for i in range(4):
            state[a].append(ord(ciphertext[i + a * 4]))
            key0[a].append(ord(clave[i + a * 4]))

    round_keys = aes.key_generation(key0)
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_keys[10][i][j]
    aes.inv_shift_rows(state)
    aes.inv_sub_bytes(state)
    for rounda in range(1, 10):
        round = 10 - rounda
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_keys[round][i][j]
        aes.inv_mix_columns(state)
        aes.inv_shift_rows(state)
        aes.inv_sub_bytes(state)
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_keys[0][i][j]
    for i in range(4):
        for j in range(4):
            state[i][j] = chr(state[i][j])
    plaintext = ''.join([''.join(row) for row in state])

    text_resultado_aes.delete("1.0", tk.END)
    text_resultado_aes.insert(tk.END, plaintext)

# -------------------------
# Ventana principal
# -------------------------

root = tk.Tk()
root.title("Cifrados Clásico y Moderno")
root.geometry("600x500")
root.resizable(False, False)

tabs = ttk.Notebook(root)
tab_cesar = ttk.Frame(tabs)
tab_aes = ttk.Frame(tabs)

tabs.add(tab_cesar, text="Cifrado César")
tabs.add(tab_aes, text="Cifrado AES")
tabs.pack(expand=1, fill="both")

# --- Tab César ---
tk.Label(tab_cesar, text="Texto:", font=("Arial", 12)).pack(pady=5)
entry_texto_cesar = tk.Text(tab_cesar, height=5, width=60)
entry_texto_cesar.pack()

tk.Label(tab_cesar, text="Desplazamiento:", font=("Arial", 12)).pack(pady=5)
entry_clave_cesar = tk.Entry(tab_cesar, width=10)
entry_clave_cesar.pack()

frame_botones_cesar = tk.Frame(tab_cesar)
frame_botones_cesar.pack(pady=10)
tk.Button(frame_botones_cesar, text="Cifrar", command=cifrar_cesar).grid(row=0, column=0, padx=5)
tk.Button(frame_botones_cesar, text="Descifrar", command=descifrar_cesar).grid(row=0, column=1, padx=5)

tk.Label(tab_cesar, text="Resultado:", font=("Arial", 12)).pack(pady=5)
text_resultado_cesar = tk.Text(tab_cesar, height=5, width=60)
text_resultado_cesar.pack()

# --- Tab AES ---
tk.Label(tab_aes, text="Texto (16 caracteres):", font=("Arial", 12)).pack(pady=5)
entry_texto_aes = tk.Text(tab_aes, height=3, width=60)
entry_texto_aes.pack()

tk.Label(tab_aes, text="Clave (16 caracteres):", font=("Arial", 12)).pack(pady=5)
entry_clave_aes = tk.Entry(tab_aes, width=20)
entry_clave_aes.pack()

frame_botones_aes = tk.Frame(tab_aes)
frame_botones_aes.pack(pady=10)
tk.Button(frame_botones_aes, text="Cifrar", command=cifrar_aes).grid(row=0, column=0, padx=5)
tk.Button(frame_botones_aes, text="Descifrar", command=descifrar_aes).grid(row=0, column=1, padx=5)

tk.Label(tab_aes, text="Resultado:", font=("Arial", 12)).pack(pady=5)
text_resultado_aes = tk.Text(tab_aes, height=5, width=60)
text_resultado_aes.pack()

# -------------------------
# Iniciar aplicación
# -------------------------
root.mainloop()

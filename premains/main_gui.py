import base64
from functions import AES as aes
from functions import Cesar as csr
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# -------------------------
# Funciones de Cifrado César
# -------------------------

def cifrar_cesar():
    texto = entry_texto_cesar.get("1.0", "end").strip()
    try:
        desplazamiento = int(entry_clave_cesar.get())
    except ValueError:
        messagebox.showerror("Error", "El desplazamiento debe ser un número entero.")
        return
    if not texto:
        messagebox.showwarning("Aviso", "Ingrese un texto para cifrar.")
        return

    resultado = csr.cesar_encrypt(texto, desplazamiento)
    text_resultado_cesar.delete("1.0", "end")
    text_resultado_cesar.insert("end", resultado)

def descifrar_cesar():
    texto = entry_texto_cesar.get("1.0", "end").strip()
    try:
        desplazamiento = int(entry_clave_cesar.get())
    except ValueError:
        messagebox.showerror("Error", "El desplazamiento debe ser un número entero.")
        return
    resultado = csr.cesar_decrypt(texto, desplazamiento)
    text_resultado_cesar.delete("1.0", "end")
    text_resultado_cesar.insert("end", resultado)

# -------------------------
# Funciones de Cifrado AES
# -------------------------

def cifrar_aes():
    mensaje = entry_texto_aes.get("1.0", "end").strip()
    clave = entry_clave_aes.get().strip()

    if len(clave) != 16:
        messagebox.showerror("Error", "La clave debe tener exactamente 16 caracteres.")
        return
    if len(mensaje) != 16:
        messagebox.showerror("Error", "El mensaje debe tener exactamente 16 caracteres.")
        return

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

    text_resultado_aes.delete("1.0", "end")
    text_resultado_aes.insert("end", texto_cifrado_b64)

def descifrar_aes():
    mensaje_cifrado_b64 = entry_texto_aes.get("1.0", "end").strip()
    clave = entry_clave_aes.get().strip()

    if len(clave) != 16:
        messagebox.showerror("Error", "La clave debe tener exactamente 16 caracteres.")
        return

    try:
        ciphertext = base64.b64decode(mensaje_cifrado_b64).decode()
    except Exception:
        messagebox.showerror("Error", "El texto cifrado no es válido o no está en Base64.")
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

    text_resultado_aes.delete("1.0", "end")
    text_resultado_aes.insert("end", plaintext)

# -------------------------
# INTERFAZ GRÁFICA
# -------------------------

app = ttk.Window(themename="superhero")
app.title("🔐 Cifrados Clásico y Moderno")
app.geometry("700x550")
app.resizable(False, False)

tabs = ttk.Notebook(app)
tab_cesar = ttk.Frame(tabs)
tab_aes = ttk.Frame(tabs)
tabs.add(tab_cesar, text="Cifrado César")
tabs.add(tab_aes, text="Cifrado AES")
tabs.pack(expand=1, fill="both", padx=10, pady=10)

# --- Cifrado César ---
ttk.Label(tab_cesar, text="Texto:", font=("Segoe UI", 11)).pack(pady=5)
entry_texto_cesar = ttk.Text(tab_cesar, height=5, width=70)
entry_texto_cesar.pack(pady=5)

ttk.Label(tab_cesar, text="Desplazamiento:", font=("Segoe UI", 11)).pack(pady=5)
entry_clave_cesar = ttk.Entry(tab_cesar, width=15)
entry_clave_cesar.pack()

frame_botones_cesar = ttk.Frame(tab_cesar)
frame_botones_cesar.pack(pady=10)
ttk.Button(frame_botones_cesar, text="Cifrar", bootstyle=SUCCESS, command=cifrar_cesar).grid(row=0, column=0, padx=5)
ttk.Button(frame_botones_cesar, text="Descifrar", bootstyle=INFO, command=descifrar_cesar).grid(row=0, column=1, padx=5)

ttk.Label(tab_cesar, text="Resultado:", font=("Segoe UI", 11)).pack(pady=5)
text_resultado_cesar = ttk.Text(tab_cesar, height=5, width=70)
text_resultado_cesar.pack(pady=5)

# --- Cifrado AES ---
ttk.Label(tab_aes, text="Texto (16 caracteres):", font=("Segoe UI", 11)).pack(pady=5)
entry_texto_aes = ttk.Text(tab_aes, height=3, width=70)
entry_texto_aes.pack(pady=5)

ttk.Label(tab_aes, text="Clave (16 caracteres):", font=("Segoe UI", 11)).pack(pady=5)
entry_clave_aes = ttk.Entry(tab_aes, width=25)
entry_clave_aes.pack()

frame_botones_aes = ttk.Frame(tab_aes)
frame_botones_aes.pack(pady=10)
ttk.Button(frame_botones_aes, text="Cifrar", bootstyle=SUCCESS, command=cifrar_aes).grid(row=0, column=0, padx=5)
ttk.Button(frame_botones_aes, text="Descifrar", bootstyle=INFO, command=descifrar_aes).grid(row=0, column=1, padx=5)

ttk.Label(tab_aes, text="Resultado:", font=("Segoe UI", 11)).pack(pady=5)
text_resultado_aes = ttk.Text(tab_aes, height=5, width=70)
text_resultado_aes.pack(pady=5)

ttk.Button(app, text="Salir", bootstyle=DANGER, command=app.destroy).pack(pady=10)

# -------------------------
# Iniciar aplicación
# -------------------------
app.mainloop()

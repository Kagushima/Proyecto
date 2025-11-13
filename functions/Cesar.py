# --------------------------------
# Funciones de cifrado y descifrado
# --------------------------------
def cesar_encrypt(texto, desplazamiento):
    resultado = ""
    for char in texto:
        if char.isalpha():
            desplazado = ord(char) + desplazamiento
            if char.islower():
                if desplazado > ord('z'):
                    desplazado -= 26
                resultado += chr(desplazado)
            elif char.isupper():
                if desplazado > ord('Z'):
                    desplazado -= 26
                resultado += chr(desplazado)
        else:
            resultado += char
    return resultado
def cesar_decrypt(texto, desplazamiento):
    return cesar_encrypt(texto, -desplazamiento)
# --------------------------------
# Funcion principal
# --------------------------------
def menuCesar():
    while True:
        print("Menu de Cifrado Cesar")
        opcion = input("\n1. Cifrar\n2. Descifrar\n3. Salir\nSeleccione una opcion: ")
        if opcion == "1":
            texto = input("Ingrese el texto a cifrar: ")
            desplazamiento = int(input("Ingrese el desplazamiento: "))
            resultado = cesar_encrypt(texto, desplazamiento)
            print("Texto cifrado:", resultado)
        elif opcion == "2":
            texto = input("Ingrese el texto a descifrar: ")
            desplazamiento = int(input("Ingrese el desplazamiento: "))
            resultado = cesar_decrypt(texto, desplazamiento)
            print("Texto descifrado:", resultado)
        elif opcion == "3":
            print("Saliendo...")
            break
        else:
            print("Opcion no valida. Intente de nuevo.")
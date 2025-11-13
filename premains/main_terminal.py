from functions import AES as aes
from functions import Cesar as csr
while True:
    print("Menu de cifrados")
    opcion = input("\n1. Cifrado César\n2. Cifrado AES\n3. Salir\nSeleccione una opción: ")
    if opcion == "1":
        csr.menuCesar()
    elif opcion == "2":
        aes.menuAES()
    elif opcion == "3":
        print("Saliendo del programa...")
        break
    else:
        print("Opción no válida. Intente de nuevo.")
import json



def UserRegister():
    fileName= input("Give me some file name: ")    
    condition=True
    users = []
    while condition:
     name = input("Enter name: ")
     if (name==""):
         condition=False 
         break
     password = input("Enter password: ")
     mail = input("Enter mail: ")
     user = {"Username: ": name, "Password: ": password, "mail: ": mail}
     users.append(user)
    with open(fileName,"w") as file:
        json.dump(users,file)
        
        
def ReadFile():
 fileName= input("What file do you want to read? ")
 with open(fileName,'r') as fileReaded:
   text = fileReaded.read()
   print(text)

def undefinedFunction():
    print("Undefined function")
    
print("------------Opciones-------------")   
print("1) Registrar Usuario ","2) Leer archivo ","3) Salir " )
 
condition = True

while condition:
  switch = {
      1: UserRegister,
      2: ReadFile,
      3: (lambda: (print("Adios"), exit()))   
  }
  x = int(input("¿Qué deseas hacer?: "))
  switch.get(x, undefinedFunction)()





# # Abrir el archivo en modo de lectura
# with open(fileName2, 'r') as archivo:
#     # Cargar el contenido del archivo en un diccionario de Python
#     datos = json.load(archivo)

# # Imprimir el diccionario
# print(datos)

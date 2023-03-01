import os
import json
import hashlib
import unicodedata
from Crypto.Cipher import AES


#---------------------------------USUARIOS---------------------------------------

def AddUser(fileName):
    condition = True
    while condition:
        if not fileExists(fileName):
                name = input("Ingrese el nombre de usuario: ")
                if(name==""):
                    condition= False
                    break
                password = input("Ingrese la contraseña: ")
                mail= input("Ingresa un email: ")
                try:
                     user= {"Username": name, "Password": FuncSha512(password), "Email":mail, "Servicios": []}
                     with open(fileName, 'w') as file:
                        json.dump([user],file)
                        print("Se ha creado el archivo")
                except:
                    print("No fue posible crear el archivo")
        else:   
                jsonData = getJson(fileName)
                printJson(jsonData)
                name = input("Ingrese el nombre de usuario: ")
                if(name==""):
                    condition= False
                    break
                password = input("Ingrese la contraseña: ")
                mail= input("Ingresa un email: ")
                mailBanner = existMail(mail, jsonData)
                if mailBanner: 
                    try:
                         user= {"Username": name, "Password": FuncSha512(password), "Email":mail, "Servicios": []}
                         jsonData.append(user)
                         
                         with open(fileName, 'w') as file:
                            json.dump(jsonData, file)
                            print("Se creo el usuario correctamente")
                    except:
                        print("No fue posible crear el usuario")
                else: print("El email ya existe, intentalo de nuevo") 
    
                
def loginUser(name, password, fileName):
    jsonData = getJson(fileName)
    for i in jsonData:
        if(i["Username"]==name and i["Password"]==FuncSha512(password)):
            print(f"-----------Bienvenid@--{name}-------------")
            return True
    print("Usuario o contraseña incorrecto")
    return False


def FuncSha512(password):
    hashSha512= hashlib.sha512(password.encode('utf-8'))
    sha512 = hashSha512.hexdigest()
    return sha512
#---------------------------------TERMINA-USUARIOS--------------------------------------

    
    



#---------------------------------SERVICIOS---------------------------------------

#ADICIÓN DE SERVICIO
def AddService(userName,password,fileName):
    jsonData = getJson(fileName)
    condition = True
    while condition:
        user = getUserData(userName,jsonData)
        name = input("Ingresa el nombre del servicio: ")
        if (name==""):
            condition = False
            break
        password = input("Ingrese la contraseña: ")
        createdBy = userName
        service = {"Service name": name,"Password":password,"Creator":createdBy}
        user["Servicios"].append(service)
        
        try: 
            with open(fileName,"w") as file:
                json.dump(jsonData,file)
                print("Se ha agregado el servicio con éxito")
        except: 
            print("Ocurrió un error")
            break

def ShowService(userName,fileName):
    jsonData = getJson(fileName)
    user = getUserData(userName,jsonData)
    services = user["Servicios"]  
    for service in services:
          print(f"- Nombre de servicio: {service['Service name']} Contraseña:  {service['Password']} Creador: {service['Creator']}")  
          
def DeleteService(userName, serviceName,fileName):
    jsonData = getJson(fileName)
    userData = getUserData(userName,jsonData)
    dropService = getServiceData(userName,serviceName,jsonData)
    userData["Servicios"].remove(dropService)
    with open(fileName, "w") as file:
        json.dump(jsonData, file)
        
def AlterService(userName, serviceName, newServiceData, fileName):
    jsonData = getJson(fileName)
    userData = getUserData(userName, jsonData)
    for serviceData in userData["Servicios"]:
        if serviceData["Service name"] == serviceName:
            serviceData.update(newServiceData)
            break
    with open(fileName, "w") as file:
        json.dump(jsonData, file)

def ServiceUpdated(name,password):
    serviceData={
        "Service name": name,
        "Password":password
    }
    return serviceData
    
    

        
#EXTRAS-----------------------------------------------------------------------------
def printJson(jsonData):
    for index, object in enumerate(jsonData):
        print(f"{index}. {object}")
        
def getUserData(userName, jsonData):
    for user in jsonData:
        if user["Username"]==userName:
            return user
        else:
            print("No se encontró usuario") 
            return None 
        
        
def getServiceData(userName, serviceName, jsonData):
    for user in jsonData:
        if user["Username"]==userName:
            services = user["Servicios"]
            for service in services:
                if service["Service name"]==serviceName:
                    return service
            print("No se encontró el servicio")
            return None    

def existMail(mail, jsonData):
    if len(jsonData)==0:
        return True
    else:    
        for i in jsonData:  
            if i["Email"] == mail:
             return False
    return True
        
            

def getJson(fileName):
    try:
        with open(fileName, 'r') as file:
            jsonData = json.load(file)
        return jsonData
    except:
        print("El json no es válido")

def fileExists(fileName):
    try:
        return os.path.isfile(fileName)
    except:
        return False
    
def subMenu(userName,userPassword,fileName):
    condition = True
    while condition:
        print(f"-----------Hola,{name}----------"," ¿Qué deseas hacer?")
        print("1) Agregar servicios", "2) Ver servicios", "3) Eliminar servicio", "4) Editar Servicio","5) Salir")
        print("")
        
        y = int(input("Ingrese la opción deseada (1,2,3,4,5)"))
        
        if y==1:
            AddService(userName, userPassword, fileName)
        elif y==2:
            print("")

            ShowService(userName,fileName)
            print("")
      
        elif y == 3:
            
            serviceName = input("Ingrese el nombre del servicio que desea eliminar: ")
            DeleteService(name,serviceName,fileName)
            
        elif y==4:
            serviceName = input("Ingrese el nombre del servicio que desea editar: ")
            newName= input("Ingresa el nuevo nombre del servicio: ")
            newPass= input("Ingresa la nueva contraseña del servicio: ")

            newServiceData = ServiceUpdated(newName,newPass)
            
            AlterService(userName, serviceName, newServiceData, fileName)
        elif y==5:
            print("Adios")
            condition=False
            exit()
            
        else: print("Ingresa una opción valida")
        

    
    
    
#------------------------------------TERMINA EXTRAS----------------------------------------------------------------------

    
    
    
    
    
#---------------------------EJECUCIÓN-DE-CÓDIGO---------------------------    
condition = True

while condition:
    
    print("------------Opciones-------------")
    print("1) Registrar Usuario ", "2) Iniciar sesión ", "3) Salir ")
    fileName = "prueba2.txt"
    
    x = int(input("Ingresa lo que desees hacer (1,2,3)"))

    if x == 1:
        AddUser(fileName)
    elif x == 2:
        name = input("Ingresa el nombre de usuario: ")
        password = input("Ingresa la contraseña: ")

        banner = loginUser(name, password, fileName)
        if banner: subMenu(name, password, fileName)
        else: print("Intentalo de nuevo")
    elif x == 3:
        condition = False
        (lambda: (print("Adios"), exit()))
    else:
        print("Ingresa una acción valida")
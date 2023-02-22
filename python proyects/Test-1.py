import hashlib
import unicodedata

def indexes(plainText):
    
 s= unicodedata.normalize("NFKD", plainText).encode("ascii","ignore").decode("ascii").lower()
 dictionary = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',',','.',' ','0','1','2','3','4','5','6','7','8','9']
 aux = plainText.upper()
 lChain = list(s)
 nChar = len(s)
 index = [0]*nChar

 for i in range(0,nChar,1):
     index[i] = dictionary.index(lChain[i])
     print(index[i])
 return index

def crypt(indexes):
    cryptonary = ['f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z', ',','.',' ','0','1','2','3','4','5','6','7','8','9','A','B','C','D','E']
    nArray = len(indexes)
    crypted = ['']*nArray
    
    for i in range(0,nArray,1):
        crypted[i] = cryptonary[(indexes[i])]
        
        output= ''.join(str(x) for x in crypted)
   
    return output

def decrypt(ciferText,sha256):
    aux = FuncSha256(ciferText)
    if (sha256==aux):
        index = indexes(ciferText)
        decryptonary = ['5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',',','.',' ','0','1','2','3','4']
        nArray = len(ciferText)
        decrypted = ['']*nArray
    
        for i in range(0,nArray,1):
            decrypted[i] = decryptonary[(index[i])]
        output= ''.join(str(x) for x in decrypted)
        
        return output
    
    elif (sha256!=aux) :
        output= 'you´r encrypted word, suffered changes'
        return output
    
    
def FuncSha256(cryptedWord):
    hashSha256 = hashlib.sha256(cryptedWord.encode('utf-8'))
    sha256 = hashSha256.hexdigest()
    return sha256

def FuncShaMd5(cryptedWord):
    hashMd5 = hashlib.md5(cryptedWord.encode('utf-8'))
    md5 = hashMd5.hexdigest()
    return md5

#Main

palabra = input("Ingresa la palabra que deseas encriptar: ")
indices = indexes(palabra)
textoCifrado = crypt(indices)
tcSha256 = FuncSha256(textoCifrado)

print(textoCifrado)
print(tcSha256)

#descencriptar

palabraCifrada = input("Ingresa la palabra que deseas decifrar: ")
tdSha256 = input("Ingrese la cadena sha256 para decifrar el texto: ")
textoDecifrado = decrypt(palabraCifrada,tdSha256)

print(textoDecifrado)
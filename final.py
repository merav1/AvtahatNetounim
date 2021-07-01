#import all the required libraries
import cv2 
import numpy as np 
import types 
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import binascii
import random


def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)
    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))  
    return "cipher_text"+ str(b64encode(cipher_text).decode('utf-8'))+"salt"+ str(b64encode(salt).decode('utf-8'))+"nonce"+ str(b64encode(cipher_config.nonce).decode('utf-8'))+"tag"+ str(b64encode(tag).decode('utf-8'))


def decrypt(enc_dict, password):
    c = enc_dict.find("cipher_text")+11
    rc = enc_dict[c:enc_dict.find("salt")]
    c = enc_dict.find("salt")+4
    rs = enc_dict[c:enc_dict.find("nonce")]
    c = enc_dict.find("nonce")+5
    rn = enc_dict[c:enc_dict.find("tag")]
    c = enc_dict.find("tag")+3
    rt = enc_dict[c:]
    salt = b64decode(rs)
    cipher_text = b64decode(rc)
    nonce = b64decode(rn)
    tag = b64decode(rt) 
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)
    return decrypted


def messageToBinary(message): 
  if type(message) == str:
    return ''.join([ format(ord(i), "08b") for i in message ]) 
  if type(message) == bytes or type(message)== np.ndarray:
   return [ format(i, "08b") for i in message ] 
  elif type(message)== int or type(message)== np.uint8:
    return format(message, "08b")
  else: 
    raise TypeError("Input type not supported")


# Function to hide the secret message into the image  
def hideData(image, secret_message):
     # calculate the maximum bytes to encode 
     n_bytes = image.shape[0] * image.shape[1] * 3 // 8 
     print("Maximum bytes to encode:", n_bytes) 
     
     #Check if the number of bytes to encode is less than the maximum bytes in the image 
     if len(secret_message) > n_bytes: 
       raise ValueError("Error encountered insufficient bytes, need bigger image or less data !!") 
     secret_message += '#####' # you can use any string as the delimeter 
     data_index = 0 
      # convert input data to binary format using messageToBinary() fucntion 
     binary_secret_msg = messageToBinary(secret_message)
     data_len= len(binary_secret_msg) #find the length of data that needs to be hidden
     rows,cols,d = image.shape
     for i in range(rows):
          for j in range(cols):
            # convert RGB values to binary format 
            r = messageToBinary(image[i][j][0]) 
            g = messageToBinary(image[i][j][1]) 
            b = messageToBinary(image[i][j][2]) 
            # modify the least significant bit only if there is still data to store 
            if data_index < data_len: 
                # hide the data into least significant bit of red pixel 
                image[i][j][0] = int(r[:-1] + binary_secret_msg[data_index], 2) 
                data_index += 1 
                if data_index < data_len: 
                    # hide the data into least significant bit of green pixel 
                    image[i][j][1] = int(g[: -1] + binary_secret_msg[data_index], 2) 
                    data_index += 1 
                if data_index < data_len: 
                    # hide the data into least significant bit of blue pixel 
                    image[i][j][2] = int(b[:-1] + binary_secret_msg[data_index], 2) 
                    data_index += 1 
                    # if data is encoded, just break out of the loop 
                if data_index >= data_len: 
                    break

     data_index =0             
     for i in range(rows-1,-1,-1):
          for j in range(cols-1,-1,-1):
            # convert RGB values to binary format 
            r = messageToBinary(image[i][j][0]) 
            g = messageToBinary(image[i][j][1]) 
            b = messageToBinary(image[i][j][2]) 
            # modify the least significant bit only if there is still data to store 
            if data_index < data_len: 
                # hide the data into least significant bit of red pixel 
                image[i][j][0] = int(r[:-1] + binary_secret_msg[data_index], 2) 
                data_index += 1 
                if data_index < data_len: 
                    # hide the data into least significant bit of green pixel 
                    image[i][j][1] = int(g[: -1] + binary_secret_msg[data_index], 2) 
                    data_index += 1 
                if data_index < data_len: 
                    # hide the data into least significant bit of blue pixel 
                    image[i][j][2] = int(b[:-1] + binary_secret_msg[data_index], 2) 
                    data_index += 1 
                    # if data is encoded, just break out of the loop 
                if data_index >= data_len: 
                    break
     return image



def showData(image): 
      rows,cols,d = image.shape
      binary_data = ""
      binary_data_end = ""
      binary_data_final = ""
      for i in range(rows):
        for j in range(cols):
          r = messageToBinary(image[i][j][0]) 
          g = messageToBinary(image[i][j][1]) 
          b = messageToBinary(image[i][j][2]) 
          binary_data += r[-1] #extracting data from the least significant bit of red pixel 
          binary_data += g[-1] #extracting data from the least significant bit of red pixel 
          binary_data += b[-1] #extracting data from the least significant bit of red pixel

      for i in range(rows-1,-1,-1):
        for j in range(cols-1,-1,-1):
          r2 = messageToBinary(image[i][j][0]) 
          g2 = messageToBinary(image[i][j][1]) 
          b2 = messageToBinary(image[i][j][2]) 
          binary_data_end += r2[-1] #extracting data from the least significant bit of red pixel 
          binary_data_end += g2[-1] #extracting data from the least significant bit of red pixel 
          binary_data_end += b2[-1] #extracting data from the least significant bit of red pixel
      # split by 8-bits 
      all_bytes = [ binary_data[i: i+8] for i in range(0, len (binary_data), 8) ] 
      # convert from bits to characters 
      decoded_data = "" 
      for byte in all_bytes: 
        decoded_data += chr(int(byte, 2)) 
        if decoded_data[-5:] == "#####": #check if we have reached the delimeter which is "#####" 
          break 
      # split by 8-bits 
      all_bytes_end = [ binary_data_end[i: i+8] for i in range(0, len (binary_data_end), 8) ] 
      # convert from bits to characters 
      decoded_data_end = "" 
      for byte in all_bytes_end: 
        decoded_data_end += chr(int(byte, 2)) 
        if decoded_data_end[-5:] == "#####": #check if we have reached the delimeter which is "#####" 
          break 
      #print(decoded_data) 
      return decoded_data[: -5],decoded_data_end[: -5] #remove the delimeter to show the original hidden message



# Encode data into image 
def encode_text(): 
    image_name = input("Enter image name (with extension): ") 
    image = cv2.imread (image_name) # Read the input image using OpenCV-Python. 
    #It is a library of Python bindings designed to solve computer vision problems. 
    #details of the image 
    print("The shape of the image is: ",image.shape) #check the shape of image to calculate the number of bytes in it 
    #print("The original image is as shown below: ") 
    resized_image = cv2.resize(image, (500, 500)) #resize the image as per your requirement 
    #cv2_imshow(resized_image) #display the image 
    data = input("Enter data to be encoded : ") 
    if (len(data) == 0): 
        raise ValueError('Data is empty') #encoded image (with extension): ") 
    f = open("password.txt",'r')
    password = f.read()
    f.close()
    encrypted = encrypt(data,password)
    print()
    filename = input("Enter the name of new encoded image(with extension):")
    encoded_image = hideData (image, encrypted) # call the hideData function to hide the secret message into the selected image 
    cv2.imwrite(filename, encoded_image)


# Decode the data in the image 
def decode_text(): 
  # read the image that contains the hidden image 
  image_name = input("Enter the name of the steganographed image that you want to decode (with extension) : ") 
  image = cv2.imread (image_name) #read the image using cv2.imread() 
  #print("The Steganographed image is as shown below: ") 
  resized_image = cv2.resize(image, (500, 500)) #resize the original image as per your requirement 
  #cv2_imshow(resized_image) #display the Steganographed image  
  text1,text2 = showData(image) 
  f = open("password.txt",'r')
  password = f.read()
  f.close()
  try:
    text1=bytes.decode(decrypt(text1,password))
    return text1
  except:
    try:
      text2=bytes.decode(decrypt(text2,password))
      return text2
    except:
      return "Unable to open encryption"


def CreateKeys():
  keyPair = RSA.generate(3072)
  pubKey = keyPair.publickey()
  pubKeyPEM = pubKey.exportKey()
  privKePEM = keyPair.exportKey()
  f = open("privKePEM.txt",'w')
  f.write(privKePEM.decode('ascii'))
  f.close()
  f = open("pubKeyPEM.txt",'w')
  f.write(pubKeyPEM.decode('ascii'))
  f.close()  


def genratorKey():
  st =""
  for i in range(16):
    st += random.choice(string.ascii_lowercase)
  return st

def CreateSemetricKey():
  st_pass=genratorKey()
  f = open("pubKeyPEM.txt",'r')
  pubKeyPEM_FromFile = f.read()
  encryptor = PKCS1_OAEP.new(RSA.importKey(pubKeyPEM_FromFile))
  encrypted = encryptor.encrypt(bytes(st_pass,'utf-8'))
  f = open("encrypted.txt",'wb')
  f.write(encrypted)
  f.close()
  f = open("password.txt",'w')
  f.write(st_pass)
  f.close()
  
def GetSemetricKey():
  f = open("encrypted.txt",'rb')
  encrypted_FromFile = f.read()
  f.close()
  f = open("privKePEM.txt",'r')
  privKePEM = f.read()
  decryptor = PKCS1_OAEP.new(RSA.importKey(privKePEM))
  decrypted = decryptor.decrypt(encrypted_FromFile)
  decrypted = str(decrypted)
  f = open("password.txt",'w')
  f.write(decrypted[2:-1])
  f.close()

# Image Steganography 
def Steganography(): 
  try:
    a = input("Image Steganography \n1. Encode the data \n2. Decode the data \n3. Create Keys \n4. Create Semetric Keys \n5. Received Semetric Keys \nYour input is: ") 
    userinput = int(a) 
    if (userinput == 1): 
      print("\nEncoding....") 
      encode_text() 
    elif (userinput == 2): 
      print("\nDecoding....") 
      print("Decoded message is " + decode_text()) 
    elif (userinput == 3): 
      CreateKeys()
      print("keys were created")   
    elif (userinput == 4): 
      CreateSemetricKey()
      print("Semetric key was created")   
    elif (userinput == 5): 
      GetSemetricKey()
      print("Semetric key was received")   
    else:
      print("Enter correct input") 
  except: 
    print("error occured") 

Steganography() #encode image
import itertools #used for permutations
from cryptography.fernet import Fernet #used for the symmetric key generation
from collections import Counter #used to count most common word
from collections import defaultdict # used to make the the distinct word list
from llist import dllist, dllistnode # python linked list library
import base64 #used for base 64 encoding
import os 
from cryptography.hazmat.backends import default_backend #used in making key from password
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC





def main():
	print("Welcome to Searchable Symmetric Encryption.\n\n")
	reply = input("Do you already have an encrypted data set? (Y)es or (N)o: ")
	while(True):
		#if yes then you have already generated keys and just want to search
		if(reply.lower() == 'y' or reply.lower() == "yes"):
			password = input("Please enter the password: ")
			break


		#if no then need to generate symmetric keys
		elif (reply.lower() == 'n' or reply.lower() == "no"):
			password = None
			while(True):
				password1 = input("Please choose a password: ")
				password2 = input("Please re-enter the password: ")
				if(password1 == password2):
					password = password1
					print("")
					break
				print("Passwords not the same try again\n")

			key_s, key_y, key_z = keygen(password)
			#uncomment out to see the three keys
			#print(key_s)
			#print(key_y)
			#print(key_z)

			word_dict = intialization()
			#uncomment out to see the word_dict list
			#for i in word_dict.items():
				#print(i)

			build_array()

			break


		#this just makes sure user enters yes or no or y or n
		else:
			reply = input("\nInput Y for yes or N for no: ")



############################################################################################

def intialization():
	filenames = []
	x = input("Please enter the name of a file you want to encrypt: ")
	filenames.append(x)
	while(True):
		x = input("\nEnter another file name or press enter if done: ")
		if not x:
			break
		filenames.append(x)
			# finds the occurence of each word in a flle
	filedata = []
	for idx, val in enumerate(filenames):
		cnt = Counter()
		for line in open(filenames[idx], 'r'):
			word_list = line.replace(',','').replace('\'','').replace('.','').lower().split()
			for word in word_list:
				cnt[word]+=1
		filedata.append((val,cnt))
			
	#takes the 5 most common from each document as the distinct words
	allwords = []
	for idx, val in enumerate(filedata):
		for value, count in val[1].most_common(5):
			if  value not in allwords:
				allwords.append(value)
		#makes a dictory with the distinct word as index and a value of a list of filenames
	word_dict = defaultdict(list)
	for i in allwords:
		word_dict[i]
		for idx, val in enumerate(filedata):
			if i in val[1]:
				word_dict[i].append(val[0])
		word_dict[i].sort()
	return word_dict



############################################################################################

def keygen(u_password):
	password_provided = u_password # This is input in the form of a string
	password = password_provided.encode() # Convert to type bytes
	salt_s = b'\x91\xabr\xebx\xc5\x9dx^b_7\xb6\x8a\xbb5' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
	salt_y = b'\x1cy8\r\x7f\xf8,\xe2Pu!/\x043\xdc\x0e'
	salt_z = b'\x9b\xd0\xb6\x85!J\xde\xe5\xc8\xb3\xc9\xa2\tqPy'
	kdf_s = PBKDF2HMAC(
	    algorithm=hashes.SHA256(),
	    length=32,
	    salt=salt_s,
	    iterations=100000,
	    backend=default_backend()
	)
	key_s = base64.urlsafe_b64encode(kdf_s.derive(password))

	kdf_y = PBKDF2HMAC(
	    algorithm=hashes.SHA256(),
	    length=32,
	    salt=salt_y,
	    iterations=100000,
	    backend=default_backend()
	)
	key_y = base64.urlsafe_b64encode(kdf_y.derive(password))

	kdf_z = PBKDF2HMAC(
	    algorithm=hashes.SHA256(),
	    length=32,
	    salt=salt_z,
	    iterations=100000,
	    backend=default_backend()
	)
	key_z = base64.urlsafe_b64encode(kdf_z.derive(password))

	#returns three base_64 encoded keys
	return key_s, key_y, key_z


############################################################################################

def build_array():
	print("Build array Part")




if __name__ == '__main__':
	main()
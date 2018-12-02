'''
Searchable Symmetric Encryption Scheme

Python Version: 3.6
Dependency: cryptography module (see README)

Implemented by Kobra Amirizirtol, Daniel Kane, Richard Nelson

Based on the work by Reza Curtmola, Seny Kamara, Juan Garay
and Rafail Ostrovsky in 'Searchable Symmetric Encryption: Improved
Definitions and Efficient Constructions'

'''


import itertools 
from itertools import permutations, combinations #used for permutations
from cryptography.fernet import Fernet #used for the symmetric key generation
from collections import Counter #used to count most common word
from collections import defaultdict # used to make the the distinct word list
from llist import dllist, dllistnode # python linked list library
import base64 #used for base 64 encoding
import os 
from cryptography.hazmat.backends import default_backend #used in making key from password
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import random #to select random key
import sys
import re
import bitarray #for lookup table


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

			word_dict = intialization()

			A, keyword_key_pair = build_array(word_dict, key_s, key_y, key_z)

			T = look_up_table(keyword_key_pair, key_s, key_y, key_z)

			print("\n\nWelcome!")
			keyword = input("\nPlease enter the keyword to search, or 'exit' to exit: ")

			while keyword != 'exit':
				
				trapdoor = Trapdoor(keyword, key_z, key_y)		

				list_of_docs = Search(T, A, trapdoor)

				print(f"\nSearch Results for \"{keyword}\":\n")
				for i in list_of_docs:
					print(i)

				keyword = input("\nPlease enter the keyword to search, or 'exit' to exit: ")

			print("\n\nGoodbye!\n")

			break

		#this just makes sure user enters yes or no or y or n
		else:
			reply = input("\nInput Y for yes or N for no: ")



############################################################################################

def intialization():
	''' 
	Prompts user for documents to be encrypted and generates the distinct 
	words in each. Returns the distinct words and the documents that contained them
	in a dictionary 'word_dict'
	'''

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
	''' Generates 3 keys, key s,y,z, based on the given password from the user. '''

	# This is input in the form of a string
	password_provided = u_password 

	# Convert to type bytes
	password = password_provided.encode() 

	salt_s = b'\x91\xabr\xebx\xc5\x9dx^b_7\xb6\x8a\xbb5'
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
def psuedo_random(key_s, ctr):
	''' A pseudorandom function based on key s, to return a value to index array A '''

	#Convert key s to decimal value
	decimal_key = int.from_bytes(key_s, byteorder=sys.byteorder)
	combined = decimal_key + ctr

	#Find a random value based on key s and counter
	random.seed(combined)
	index = random.randrange(0, 10000)
	return index

############################################################################################
def build_array(word_dict, key_s, key_y, key_z):
	'''
	Creates an array of nodes, each containing the document id, key to encrypt the
	next node, and the address of the next node
	'''

	A = [0] * 10000
	ctr = 1
	keyword_key_pair = []

	#for each word in set of distinct words, word_dict in this case	
	for i, doc_list in word_dict.items():

		#Generate a key for the first node
		K_i_0 = Fernet.generate_key()
		keyword_key_pair.append([i, K_i_0, ctr])

		#initialize the previous key to the first one created
		K_i_jminus1 = K_i_0 
		
		# for 1 <= j <= |D(wi)|:
		# for each document which has distinct word wi....iterate through doc_list
		for j, doc in enumerate(doc_list):
			
			#again generate key K(i,j)
			K_i_j = Fernet.generate_key()

			#N(i,j) = (id(D(i,j) || K(i,j) || v(s)(ctr+1)), where id(D(i,j) is the jth identifier in D(wi)
	
			curr_addr = psuedo_random(key_s, ctr)
			if j == len(doc_list) - 1:
				next_addr = None
			else:
				next_addr = psuedo_random(key_s, ctr+1)
			
			N = doc + "\n" + str(K_i_j) + "\n" + str(next_addr)
			#newline is a delimeter to separate three components of the encrypted string
			#N = doc + K_i_j + address of next node. 

			#encrypt N with Ki,j-1, ie the previous key
			N = Fernet(K_i_jminus1).encrypt(str.encode(N))

			#update and save K at i,j-1
			K_i_jminus1 = K_i_j 

			#store the encrypted N in the array
			A[curr_addr] = N
	
			#update counter
			ctr = ctr + 1

	# Filling in the rest of the array with random encrypted data
	for ind,val in enumerate(A):
		if (val == 0):
			x = random.randrange(0, 10000)
			x = str(x)
			x = Fernet(key_s).encrypt(str.encode(x))
			A[ind] = x


	return A, keyword_key_pair

############################################################################################
def look_up_table(keyword_key_pair,key_s, key_y, key_z):
	'''
	Generates a table which stores the XORed result of permutation
	function f_y and the address of a node concatenated with the key
	'''
	T = [0] * 1000
	for i in keyword_key_pair:
		keyword = i[0]
		key = i[1]
		ctr = i[2]

		# pseudorandom permutation on z
		random.seed(keyword + str(key_z))
		index = random.randrange(0, 1000)

		#computes value <addr(A(Ni,1)||K_i_0)>
		addr = psuedo_random(key_s,ctr)
		value = str(addr) + "\n" + str(key)

		#computed 'f_y(w_i)'
		random.seed(keyword + str(key_y))
		f_y = random.randrange(0,1000)

		#XOR value with f_y
		cat_string = []	#empty string to begin
		for m in value:
			#concatenate ascii value of each character in value
			cat_string.append(ord(m))

		value = [f_y ^ x for x in cat_string]

		T[index] = value
	

	#set all elements equal to zero as some random key value
	for ind,val in enumerate(T):
		if (val == 0):
			x = random.randrange(0, 10000)
			x = str(x)
			x = Fernet(key_s).encrypt(str.encode(x))
			T[ind] = x
	return T

def Trapdoor(keyword, key_z, key_y):
	'''
	returns the permutation function
	and pseudorandom permutation function on keyword
	'''
	random.seed(keyword + str(key_z))
	index = random.randrange(0, 1000)
	
	#the pseudo-random function 'f_y(w)'
	random.seed(keyword + str(key_y))
	f_y = random.randrange(0,1000)

	return (index, f_y)


def Search(T, A, trapdoor):
	'''
	Indexes both T and A with trapdoor values generated by keyword 
	in main to find and decrypt the document ids
	'''

	list_of_docs = []

	value = T[trapdoor[0]]

	f_y = trapdoor[1]

	#XORs the ascii value with f_y to obtain list version of string 
	#	containing the address and the key for the node
	addr_and_key = [chr(f_y ^ x) for x in value]
	
	#converts the list into one string
	mystring = ''
	for x in addr_and_key:
		mystring = mystring + x

	#addr_node is a list.
	addr_node = re.split(r"\n", str(mystring))

	#if addr_node isn't two separate items, we didn't find a document
	if len(addr_node) == 1:
		print("\n")
	else:

		addr = addr_node[0]
		key = addr_node[1]

		#remove b' at the beginning and ' at the end
		key = key[2:-1]

		#get the node based on the address from array A
		node = A[int(addr)]

		#turn key back into bytes and use Fernet function to 
		#	decrypt back to plaintext
		decrypted_node = Fernet(str.encode(key)).decrypt(node)
		
		#remove b' at the beginning and ' at the end
		d_n = str(decrypted_node)[2:-1]
		split_node = re.split(r"\\n", d_n)
		doc_id = split_node[0]
		key = split_node[1]
		addr = split_node[2]

		list_of_docs.append(doc_id)

		#Repeat iterating while the address is not null, meaning
		#	 there are still documents with the keyword
		while addr != 'None':
			key = key[2:-1]
			key = str.encode(key)
			node = A[int(addr)]
			decrypted_node = Fernet(key).decrypt(node)
			d_n = str(decrypted_node)[2:-1]
			split_node = re.split(r"\\n", d_n)
			doc_id = split_node[0]
			key = split_node[1]
			addr = split_node[2]
			list_of_docs.append(doc_id)

	return list_of_docs

if __name__ == '__main__':
	main()

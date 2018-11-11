import itertools #used for permutations
from cryptography.fernet import Fernet #used for the symmetric key generation
from collections import Counter #used to count most common word
from collections import defaultdict # used to make the the distinct word list






def main():
	print("Welcome to Searchable Symmetric Encryption.\n\n")
	reply = input("Do you already have an encrypted data set? (Y)es or (N)o: ")
	while(True):
		#if yes then you have already generated keys and just want to search
		if(reply.lower() == 'y' or reply.lower() == "yes"):
			s = input("Please enter your s key: ")
			y = input("Please enter your y key: ")
			z = input("Please enter your z key: ")
			break
		#if no then need to generate symmetric keys
		elif (reply.lower() == 'n' or reply.lower() == "no"):
			s = Fernet.generate_key()
			y = Fernet.generate_key()
			z = Fernet.generate_key()
			print("Here is your s key ", s.decode("ascii"))
			print("Here is your y key ", y.decode("ascii"))
			print("Here is your z key ", z.decode("ascii"))
			print("\n\nThese keys are very important must keep secret and must not lose!!!!\n\n")
			#Generated keys and printed to screen


			#Gets filenames from the user 
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
			#uncomment out to see the word_dict list
			#for i in word_dict.items():
				#print(i)

			break

		#this just makes sure user enters yes or no or y or n
		else:
			reply = input("\nInput Y for yes or N for no: ")











if __name__ == '__main__':
	main()
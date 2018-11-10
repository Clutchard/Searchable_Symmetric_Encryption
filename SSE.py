import itertools #used for permutations
from cryptography.fernet import Fernet #used for the symmetric key generation
from collections import Counter
from collections import defaultdict






def main():
	print("Welcome to Searchable Symmetric Encryption.\n\n")
	reply = input("Do you already have an encrypted data set? (Y)es or (N)o: ")
	while(True):
		if(reply.lower() == 'y' or reply.lower() == "yes"):
			s = input("Please enter your s key: ")
			y = input("Please enter your y key: ")
			z = input("Please enter your z key: ")
			break
		elif (reply.lower() == 'n' or reply.lower() == "no"):
			s = Fernet.generate_key()
			y = Fernet.generate_key()
			z = Fernet.generate_key()
			print("Here is your s key ", s.decode("ascii"))
			print("Here is your y key ", y.decode("ascii"))
			print("Here is your z key ", z.decode("ascii"))
			print("\n\nThese keys are very important must keep secret and must not lose!!!!\n\n")
			filenames = []
			x = input("Please enter the name of a file you want to encrypt: ")
			filenames.append(x)
			while(True):
				x = input("\nEnter another file name or press enter if done: ")
				if not x:
					break
				filenames.append(x)
			filedata = []
			for idx, val in enumerate(filenames):
				cnt = Counter()
				for line in open(filenames[idx], 'r'):
					word_list = line.replace(',','').replace('\'','').replace('.','').lower().split()
					for word in word_list:
						cnt[word]+=1
				filedata.append((val,cnt))
			
			allwords = []
			for idx, val in enumerate(filedata):
				for value, count in val[1].most_common(5):
					if  value not in allwords:
						allwords.append(value)

			word_dict = defaultdict(list)
			for i in allwords:
				word_dict[i]
				for idx, val in enumerate(filedata):
					if i in val[1]:
						word_dict[i].append(val[0])

			for i in word_dict.items():
				print(i)
			answer = input("What word you want to see")
			print(word_dict[answer])

			break
		else:
			reply = input("\nInput Y for yes or N for no: ")











if __name__ == '__main__':
	main()
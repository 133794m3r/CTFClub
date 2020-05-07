#!/usr/bin/env python3
"""
RSA Lab. Basic Utility Really.
By Macarthur Inbody
AGPLv3 or Later
2020 -

"""
import math
def common_modulus_attack(c1,c2,e1,e2,N):
	a=0;
	b=0;
	mx=0;
	my=0;
	i=0;

	if gcd_fast(e1,e2)[0] != 1:
		raise ValueError('e1 and e2 are invalid.')
	a=mod_inv(e1,e2)
	b=(gcd_fast(e1,e2)[0] - e1 * a ) // e2
	i=mod_inv(c2,N)
	mx=pow(c1,a, N)
	my=pow(i,-b, N)

	return (mx*my) % N

def radford_ascii_decode(encoded_number,length):
	i=0;
	j=0;
	val=0;
	tmp='';
	output_str='';
	length=length-1;
	num_len=len(encoded_number)
	for i in range(0,length):
		tmp=encoded_number[j]
		if tmp == '1':
			chars=3
		else:
			chars=2

		tmp=encoded_number[j:j+chars]
		val=int(tmp)

		output_str=output_str+chr(val)
		j=j+chars
		if len(encoded_number[j:]) < 2:
			break

	return output_str

# Encodes any string of ASCII(7bit) characters into a number the way that Radford has
# done it for the chal.
def radford_ascii_encode(string_to_encode,string_length):
	tmp_str='';
	output_str='';

	tmp=0;
	i=0;

	for i in range(0,string_length):
		tmp=ord(string_to_encode[i:i+1])
		tmp_str=str(tmp)
		output_str=output_str+tmp_str

	encoded_number=output_str

	return encoded_number


# this decodes a string of bytes(ASCII text only really otherwise you need to convert it
# to a byte stream.
def rsa_ascii_encode(string_to_encode,string_length):
	tmp_str='';
	output_str='';
	x=0;
	string_to_encode=string_to_encode[::-1]
	tmp=0;
	os=[]
	i=0
	while i<string_length:
		tmp=ord(string_to_encode[i:i+1])
		x+=(tmp*pow(256,i))
		i+=1

	return x


#This converts the number to a string out of it.
def rsa_ascii_decode(x,x_len):
	X = []
	i=0;
	string=''
	#max_len=len(x)
	if x>=pow(256,x_len+1):
		raise ValueError('Number is too large to fit in output string.')

	while x>0:
		X.append(int(x % 256))
		x //=256
	for i in range(x_len-len(X)):
		X.append(0)
	X=X[::-1]
	for i in range(len(X)):
		string+=chr(X[i])

	return string
'''
This function implements carmicheal's totient to get the value utilized for generating
the multiplicative inverse of the values later one. Carmicheal's is a lot faster than
the default method represented in the original paper of PHI(p-1*q-1) which requires
a crapton of cputime to count all of the primes in the set. This is much faster.

'''
def calc_lamda(p,q):
	lamda_n=0;
	lamda_n=fast_lcm(p-1,q-1)

	return lamda_n
# Calculates the private key d wherein the following conditions are met.
# d=(e**-1) mod lamda_n. Thus d*e = 1 % lamda_n
# It utilizes previously defined functions for the calculation and works with
# the test vectors.

def calc_d(e,lamda_n):
	d=0
	d=mod_inv(e,lamda_n)

	return d

'''
Calculates the ciphertext using the pure math model for RSA Encryption.
Via the following formula. c=(m**e) % N
Returns the cipher number c.
'''
def rsa_encrypt(m,e,N):
	c=0
#	c=(pow(m,e,N) % N)
	c=pow(m,e,N)

	return c

'''
Implements RSA Decryption via the mathematical formula.
The formula is m=(c**d) % N
Returns the plain "text" really integer representation of the value.
'''
def rsa_decrypt(c,d,N):
	m=0
	m=pow(c,d,N)

	return m

'''
gcd calculator using the Generalized Extended Euclidean Algorithm.

Python implementation of the extended euclidean algorithm for calculating the gcd.
This code is the recursive variant as it is simpler.

'''
def gcd_fast(a,b):
	gcd=0;
	x=0;
	y=0;
	x=0
	#if a or b is zero return the other value and the coeffecient's accordingly.
	if a==0:
		return (b,0,1)
	elif b==0:
		return (a,0,1)
	#otherwise actually perform the calculation.
	else:
		#set the gcd x and y according to the outputs of the function.
		# a is b (mod) a. b is just a.
		gcd, x, y = gcd_fast(b % a, a)
		#we're returning the gcd, x equals y - floor(b/a) * x
		# y is thus x.
		return (gcd, y - ( b // a ) * x, x)

# Calculates the moduler multiplicative inverse of a and the modulus value
# such that a * x = 1 % mod
# Also mod is the modulus.
# % is the modulus operator in python.
# This version is a generalization and improvement upon the standard extended euclidean algorithm
# It is improved and works for all values a,m set Z.
# That means for all values of a and m that are real integers.
def mod_inv(a,mod):
	gcd=0;
	x=0;
	y=0;
	x=0;
	a_sign=(a < 0)? -1:1;
	sign_mod=(mod < 0)?-1:1;
	a*=a_sign;
	mod*=mod_sign;
	#use the extended euclidean algorithm to calculate the gcd and also bezout's coeffecients x and y.
	gcd, x, y = gcd_fast(a,mod)
	#if the gcd is not 1 or -1 tell them that it's impossible to invert.
	if gcd not in (-1,1):
		raise ValueError('Inputs are invalid. No modular multiplicative inverse exists between {} and {} gcd:{}.\n'.format(a,mod,gcd))
	#otherwise do the inversion.
	else:
		if(sign_a != 1) and (sign_mod !=1):
			return -1*((x+mod)%mod);
		else:
			return x%mod;



# A fast LCM calculator utilizing the extended euler algorithm.
def fast_lcm(a,b):
	lcm=0;
	gcd=0;

	if a==0 or b==0:
		return 0
	elif a==1:
		return b
	elif b==1:
		return a

	gcd=gcd_fast(a,b)[0]
	lcm=(a//gcd)*b

	return lcm

#this function requires sympy to be installed for it to work.
def fermats_factor(n):
	from sympy import integer_nthroot
	from sympy.ntheory.primetest import is_square
	tmp = integer_nthroot(n,2)
	a=tmp[0]
	b = pow(a,2) - n
	k=0;
	bool=tmp[1]
	
	while not is_square(b):
		a+=1
		b = pow(a,2) - n

		k+=1
		
	p = a + integer_nthroot(b,2)[0]
	q = a - integer_nthroot(b,2)[0]
	
	print(('fermat iters:{}').format(k))
	return (p,q)

	
def encrypt_rsa():
	n=int(input("Enter your modulus n: "))
	e=int(input("Enter your public key exponent e: "))
	n_bits=int(math.log(n)/math.log(2) +1)
	max_m=n_bits//10
	encoding_type=int(input("Enter your preferred encoding type\n \033[1m1:\033[0mRadford \033[1m2\033[0m:RSA Standard"))
	if encoding_type == 1:
		max_m=n_bits //15
	else:
		max_m=n_bits //10
	
	print(f"The string you will encrypt cannot be more than {max_m} characters. Any longer and it'll just cutoff the string there.")
	m=input("Enter the string you'd like to encrypt: ")
	if encoding_type == 1:
		M=radford_ascii_encode(m,len(m))
	else:
		M=rsa_ascii_encode(m,len(m))
	
	print("Your cipher text ingter is",rsa_encrypt(M,e,n))
	

def decrypt_rsa():
	print("RSA Decryptor")
	encoding = int(input("Was it encoded as Radford's way of RSA?\n\033[1m1: \033[0mRadford\n\033[1m2: \033[0mRSA Standard\n"))

	print("Are the vectors in a file? Must be in format. Cipher-text Integer->decryption exponent->modulus n.\nY/N")
	have_file=input()
	if have_file in ["Y","Yes","yes","y"]:
		fn=input("Enter file name: ")
		with open(fn,'r') as fh:
			lines=fh.readlines()
		fh.close()			
		Ct=int(lines[0])
		d=int(lines[1])
		n=int(lines[2])
	else:
		n=int(input("Enter the modulus n: "))
		have_d=input("Do you have the private key exponent d? Y/N")
		if have_d not in ["Y","y"]:
			e=int(input("Enter e: "))
			p=int(input("Enter p: "))
			q=int(input("Enter q: "))
			lambda_n=calc_lamda(p,q)
			d=calc_d(e,lambda_n)
		Ct=int(input("Enter the ciphertext integer: "))
	n_bits=int(math.log(n)/math.log(2) +1)
	
	if encoding == 1:
		m_len=n_bits // 15
	else:
		m_len=n_bits //10	
	

	

	M=rsa_decrypt(Ct,d,n)
	if encoding == 1:
		M=str(M)
		m=radford_ascii_decode(M,m_len)
	else:
		m=rsa_ascii_decode(M,m_len)
	
	print("The plaintext is\n{} \n".format(m))

#for this to work you have to install sympy.
#run the command below and remove the """ to allow this to work.
#pip3 install sympy 

def fermat_near_prime_attack():
	print("Fermat Factorer")
	n=int(input("Enter n: "))
	e=int(input("Enter e: "))
	Ct=int(input("Enter the ciphertext integer: "))
	p,q=fermats_factor(n)
	lambda_n=calc_lamda(p,q)
	d=calc_d(e,lambda_n)
	M=rsa_decrypt(Ct,d,n)
	encoding=int(input("Was the message encrypted with Radford's encoding or Standard RSA?\n\033[1m1:\033[0m Radford\n\033[1m2:\033[0mStock RSA\n"))
	n_bits=int(math.log(n)/math.log(2) +1)

	if encoding == 1:
		m_len=n_bits // 15
		M=str(M)
		m=radford_ascii_decode(M,len(M))
	else:
		print(n_bits // 10)
		print(M)	
		m_len=n_bits // 10
		m=rsa_ascii_decode(M,m_len)
	print("The found string was: {}".format(m))

def nth_root(val, n):
    ret = int(val**(1./n))
    return ret + 1 if (ret + 1) ** n == val else ret

def hba3_attack():
	from sympy import integer_nthroot
	print("Hastad Broadcast Attack")
	print("""Each number must be on a certain line. e.g.
0 cipher-text integer (C1)
1 exponent_1 (e1)
3 modulus n. (n1)
4 ciphter-text integer 2 (C2)
5 exponent 2 (e2)
6 modulus n. (2)
7 cipher-text integer (C3)
8 exponent_1 (e3)
9 modulus n. (n3)
\nThe first value is the line number. They must be in that exact order for this to work. Or at least it must be cipher-text->exponent, cipher-text->exponent, and finally n.""")
	print("Are you vectors in a file? Y/N")
	choice = input()
	if choice in ["Y","y","Yes","YES"]:
		fn=input("Enter the file's name: ")
		with open(fn,'r') as fh:
			lines=fh.readlines()
		
		c1=int(lines[0])
		e1=int(lines[1])
		n1=int(lines[2])
		c2=int(lines[3])
		e2=int(lines[4])
		n2=int(lines[5])		
		c3=int(lines[6])
		e3=int(lines[7])
		n3=int(lines[8])
		c4=int(lines[9])
		e4=int(lines[10])
		n4=int(lines[11])
		c5=int(lines[12])
		e5=int(lines[13])
		n5=int(lines[14])		
	else:
		c1=int(input("Enter ciphertext integer 1: "))	
		e1=int(input("Enter public key exponent e 1: "))	
		n1=int(input("Enter the modulus n1: "))			
		c2=int(input("Enter ciphertext integer 2: "))		
		e2=int(input("Enter public key exponent e 1: "))	
		n1=int(input("Enter the modulus n1: "))	
		c3=int(input("Enter ciphertext integer 2: "))		
		e3=int(input("Enter public key exponent e 1: "))					
		n3=int(input("Enter the modulus n1: "))		
		c4=int(lines[0])
		e4=int(lines[1])
		n4=int(lines[4])
		c5=int(lines[0])
		e5=int(lines[1])
		n5=int(lines[4])
			
	N=(n1*n2*n3*n4*n5)
	N1=n2*n3*n4*n5
	N2=n1*n3*n4*n5
	N3=n1*n2*n4*n5
	N4=n1*n2*n3*n5
	N5=n1*n2*n3*n4
	d1=mod_inv(N1,n1)
	d2=mod_inv(N2,n2)
	d3=mod_inv(N3,n3)
	d4=mod_inv(N4,n4)
	d5=mod_inv(N5,n5)

	x1=(c1*N1*d1)
	x2=(c2*N2*d2)
	x3=(c3*N3*d3)
	x4=(c4*N4*d4)
	x5=(c5*N5*d5)


	X=(x1+x2+x3+x4+x5) % N
	#t=nth_root(X,5)
	t=integer_nthroot(X,5)[0]
	n_bits=int(math.log(n1)/math.log(2) +1)	
	encoding=int(input("Was the message encrypted with Radford's encoding or Standard RSA?\n\033[1m1:\033[0m Radford\n\033[1m2:\033[0mStock RSA\n"))
	if encoding == 1:
		m_len=n_bits // 15
		M=str(M)
		m=radford_ascii_decode(t,len(M))
	else:
		m_len=n_bits //10
		m=rsa_ascii_decode(t,m_len)
	print("The found string was: {}".format(m))

def crt_common_mod():
	print("Common Modulus Attack")
	print("If they are in a file they must be formatted like so.")
	print("""Each number must be on a certain line. e.g.
0 cipher-text integer (C1)
1 exponent_1 (e1)
2 ciphter-text integer 2 (c2)
3 exponent 2 (e2)
4 modulus n. (n)
\nThe first value is the line number. They must be in that exact order for this to work. Or at least it must be cipher-text->exponent, cipher-text->exponent, and finally n.""")
	print("Are you vectors in a file? Y/N")
	choice=input()
	if choice in ["Y","y","yes","Yes"]:
		fn=input("Enter the file's name: ")
		with open(fn,'r') as fh:
			lines=fh.readlines()
		fh.close()
		c1=int(lines[0])
		e1=int(lines[1])
		c2=int(lines[2])
		e2=int(lines[3])
		n=int(lines[4])
	else:
		c1=int(input("Enter ciphertext integer 1: "))
		c2=int(input("Enter ciphertext integer 2: "))
		e1=int(input("Enter public key exponent e 1: "))
		e2=int(input("Enter public key exponent e 1: "))	
		n=int(input("Enter the modulus n: "))
	M=common_modulus_attack(c1,c2,e1,e2,n)
	n_bits=int(math.log(n)/math.log(2) +1)	
	encoding=int(input("Was the message encrypted with Radford's encoding or Standard RSA?\n\033[1m1:\033[0m Radford\n\033[1m2:\033[0mStock RSA\n"))
	if encoding == 1:
		m_len=n_bits // 15
		M=str(M)
		m=radford_ascii_decode(M,len(M))
	else:
		m_len=n_bits //10
		m=rsa_ascii_decode(M,m_len)
	print("The found string was: {}".format(m))
	
def main():
	choice=0
	while choice != 5:
		print("""Welcome to the RSA Lab. Select and option to carry out the operation.
\033[1m1:\033[0m Encrypt RSA
\033[1m2:\033[0m Decrypt RSA
\033[1m3:\033[0m Carry out Common Modulus Attack
\033[1m4:\033[0m Fermat Near Prime Factorization Attack Not working yet. Must install sympy.
\033[1m6:\033[0m Hastad Broadcast Attack
\033[1m5:\033[0m Exit
			""")
		choice=int(input())
		if choice == 1:
			encrypt_rsa()
			break
		elif choice == 2:
			decrypt_rsa()
			break
		elif choice == 3:
			crt_common_mod()
			break
		elif choice == 4:
			#uncomment next line and recomment one after that to enable this option.
			fermat_near_prime_attack()
			break
		elif choice == 6:
			
			hba3_attack()
			break
		elif choice == 5:
			break

if __name__ == "__main__":
	main()

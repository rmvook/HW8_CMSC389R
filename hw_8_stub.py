# do `curl http://starship.python.net/~gherman/programs/md5py/md5py.py > md5.py`
# if you do not have it from the git repo
import md5py, socket, hashlib, string, sys, os, time

f = open("output.txt", "w")

host = "159.89.236.106"   # IP address or URL
port = 5678 # port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
data = s.recv(1024)
print(data)
#####################################
### STEP 1: Calculate forged hash ###
#####################################

one = "1\n"
s.send(one)			     
data = s.recv(1024)
print(data)

message = 'blahah'    # original message here

s.send(message + "\n")			     
data = s.recv(1024)
print(data)
temp = data[40:] 
legit = temp.strip()
print(legit)  
f.write("Hash from which I based my crafted hash: " + legit + "\n")
# a legit hash of secret + message goes here, obtained from signing a message

# initialize hash object with state of a vulnerable hash
fake_hash = md5py.new('A' * 64)
fake_hash.A, fake_hash.B, fake_hash.C, fake_hash.D = md5py._bytelist2long(legit.decode('hex'))

malicious = 'bluhuh'  # put your malicious message here

# update legit hash with malicious message
fake_hash.update(malicious)

# test is the correct hash for md5(secret + message + padding + malicious)
test = fake_hash.hexdigest()
print("Testing fake" + test)
f.write("Fake hash" + test + "\n")


#############################
### STEP 2: Craft payload ###
#############################

# TODO: calculate proper padding based on secret + message
# secret is 6 bytes long (48 bits)
# each block in MD5 is 512 bits long
# secret + message is followed by bit 1 then bit 0's (i.e. \x80\x00\x00...)
# after the 0's is a bye with message length in bits, little endian style
# (i.e. 20 char msg = 160 bits = 0xa0 = '\xa0\x00\x00\x00\x00\x00\x00\x00\x00')
# craft padding to align the block as MD5 would do it
# (i.e. len(secret + message + padding) = 64 bytes = 512 bits
nulls = "\x00" * 43
end = "\x00" * 7 
padding = "\x80" + nulls + "\x60" + end
# payload is the message that corresponds to the hash in `test`
# server will calculate md5(secret + payload)
#                     = md5(secret + message + padding + malicious)
#                     = test
payload = message + padding + malicious

print("PAYLOAD: " + payload)
# send `test` and `payload` to server (manually or with sockets)
# REMEMBER: every time you sign new data, you will regenerate a new secret!
f.write("PAYLOAD: " + payload + "\n")


two = "2\n"
s.send(two)	#telling the server that I want to verify a hash.	     
data = s.recv(1024)
print(data)

s.send(test + "\n")	

data = s.recv(1024)
print(data)

s.send(payload + "\n")	

data = s.recv(1024) # was not receiving everything, so did it twice.
print(data)
data = s.recv(1024)
print(data)

s.close()# close the connection
f.close()#close the file
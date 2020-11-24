import requests
# TODO: import additional modules as required
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import json
import base64
import datetime
import os


gt_username = 'ywan33'   # TODO: Replace with your gt username within quotes
server_name = 'secure-shared-store'

''' <!!! DO NOT MODIFY THIS FUNCTION !!!>'''
def post_request(server_name, action, body, node_certificate, node_key):
	'''
		node_certificate is the name of the certificate file of the client node (present inside certs).
		node_key is the name of the private key of the client node (present inside certs).
		body parameter should in the json format.
	'''
	
	request_url= 'https://{}/{}'.format(server_name,action)
	request_headers = {
		'Content-Type': "application/json"
		}
	
	response = requests.post(
		url= request_url,
		data=json.dumps(body),
		headers = request_headers,
		cert = (node_certificate, node_key),
	)
	with open(gt_username, 'w') as f:
		f.write(response.content)
	return response

''' You can begin modification from here'''
def login():
	'''
		# TODO: Accept the
		- user-id
		- name of private key file(should be
		present in the userkeys folder) of the user.
		Generate the login statement as given in writeup and its signature.
		Send request to server with required parameters (action = 'login') using
		post_request function given.
		The request body should contain the user-id, statement and signed statement.
	'''
	success=''
	while success!=1:
		userId=raw_input("Enter user Id here (1): ")
		try:
			userId=int(userId)
			userId=str(userId)
		except:
			exit()
		keyName=raw_input("Enter name of private key (user1): ")
		statement= os.path.basename(os.path.dirname(os.path.realpath(__file__)))+" as user"+userId+" logs into the server"
		print statement
		try:
			key=RSA.importKey(open('userkeys/'+keyName+'.key','r'))
			success=1
		except IOError:
			print "File name of key does not exist. Try again."
	signature=(base64.b64encode(pkcs1_15.new(key).sign(SHA256.new(statement)))).decode('utf-8')
	key=''
	data={
		'userId': userId,
		'statement':statement,
		'signature':signature,
	}

	body=json.dumps(data)	
	post_request(server_name,'login',body,'certs/node1CA.crt','certs/node1CA.key')
	return 

def checkin():
	'''
		# TODO: Accept the
		- DID
		- security flag (1 for confidentiality  and 2 for integrity)
		Send the request to server with required parameters (action = 'checkin') using post_request().
		The request body should contain the required parameters to ensure the file is sent to the server.
	'''
	did=raw_input("Enter unique document name (1.txt):")
	flag=raw_input("Enter security flag (1-confidentiality, 2-integrity):")
	if os.path.exists("documents/checkin/"+did): 
		fin = open('documents/checkin/'+did, 'r')
	elif os.path.exists("documents/checkout/"+did):
		fin = open('documents/checkout/'+did, 'r')
		f = open("documents/checkin/"+did,"w")
		f.write(fin.read())
		f.close()
		os.remove("documents/checkout/"+did) 
	else:
		print "Document does not exist on client side."
		return

	data={
		'did':did,
		'flag':flag,
		'contents': fin.read(),
		'session_token':json.load(open(gt_username,"r"))["session_token"],

	}
	body=json.dumps(data)

	post_request(server_name,'checkin',body,'certs/node1CA.crt','certs/node1CA.key')
	
	return

def checkout():
	'''
		# TODO: Accept the DID.
		Send request to server with required parameters (action = 'checkout') using post_request()
	'''
	did=raw_input("Enter unique document name (1.txt):")
	data={
		'did':did,
		'session_token':json.load(open(gt_username,"r"))["session_token"],
	}
	body=json.dumps(data)	
	post_request(server_name,'checkout',body,'certs/node1CA.crt','certs/node1CA.key')
	
	if json.load(open(gt_username,"r"))["status"]==200:
		contents=json.load(open(gt_username,"r"))["contents"]
		did=json.load(open(gt_username,"r"))["did"]
		f=open("documents/checkout/"+did,"w")
		f.write(contents)
		f.close()
	return

def grant():
	'''
		# TODO: Accept the
		 - DID
		 - target user to whom access should be granted (0 for all user)
		 - type of acess to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
		 - time duration (in seconds) for which acess is granted
		Send request to server with required parameters (action = 'grant') using post_request()
	'''

	did=raw_input("Enter unique document name (1.txt):")
	userId=raw_input("User ID to whom access should be granted (0 for all users):")
	try:
		userId=int(userId)
	except:
		exit()
	accessRight=0
	while int(accessRight)<1 or int(accessRight)>3:
		accessRight=raw_input("Type of acesss to be granted (1 - checkin, 2 - checkout, 3 - both):")
	expire_date=raw_input("Time duration (in seconds) for access:")
	try:
		expire_date=int(expire_date)
	except:
		exit()

	data={
		'did':did,
		'session_token':json.load(open(gt_username,"r"))["session_token"],
		'accessRight':accessRight,
		'userId':userId,
		'expire_date':expire_date,
	}
	body=json.dumps(data)	
	post_request(server_name,'grant',body,'certs/node1CA.crt','certs/node1CA.key')
	
	return

def delete():
	'''
		# TODO: Accept the DID to be deleted.
		Send request to server with required parameters (action = 'delete')
		using post_request().
	'''
	did=raw_input("Enter unique document name (1.txt):")
	data={
		'did':did,
		'session_token':json.load(open(gt_username,"r"))["session_token"],
	}
	body=json.dumps(data)	
	post_request(server_name,'delete',body,'certs/node1CA.crt','certs/node1CA.key')
	return

def logout():
	'''
		# TODO: Ensure all the modified checked out documents are checked back in.
		Send request to server with required parameters (action = 'logout') using post_request()
		The request body should contain the user-id, session-token
	'''
	data={
		'session_token':json.load(open(gt_username,"r"))["session_token"],
	}
	body=json.dumps(data)	
	post_request(server_name,'logout',body,'certs/node1CA.crt','certs/node1CA.key')
	
	exit() #exit the program

def main():
	
	option=''
	while option=='':
		login()
		if (json.load(open(gt_username,"r")))["status"]==200:
			option=0
		else:
			print "Error: "+(json.load(open(gt_username,"r")))["message"]
	
	while (option != '5'):
		option=raw_input('''Enter the option's number: 
				1. Checkin
				2. Checkout
				3. Grant
				4. Delete
				5. Logout 
		''')
		if option=='1': checkin()
		if option=='2': checkout()
		if option=='3': grant()
		if option=='4': delete()
		if option=='5': logout()
		if (json.load(open(gt_username,"r")))["status"]!=200:
			print "Error: "+(json.load(open(gt_username,"r")))["message"]
	exit()
	
	'''
		# TODO: Authenticate the user by calling login.
		If the login is successful, provide the following options to the user
			1. Checkin
			2. Checkout
			3. Grant
			4. Delete
			5. Logout
		The options will be the indexes as shown above. For example, if user
		enters 1, it must invoke the Checkin function. Appropriate functions
		should be invoked depending on the user input. Users should be able to
		perform these actions in a loop until they logout. This mapping should 
		be maintained in your implementation for the options.
	'''

if __name__ == '__main__':
	main()


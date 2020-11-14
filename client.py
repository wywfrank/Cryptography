import requests
# TODO: import additional modules as required
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import json
import base64


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
	userId=raw_input("Enter user Id here (1): ")
	keyName=raw_input("Enter name of private key (user1): ")

	statement="client1 as user"+userId+" logs into the server"
	key=RSA.importKey(open('userkeys/'+keyName+'.key','r'))
	h=SHA256.new(statement)
	signature=(base64.b64encode(pkcs1_15.new(key).sign(h))).decode('utf-8')
	key=''

	data={
		'userId':userId,
		'statement':statement,
		'signature':signature,
	}

	body=json.dumps(data)
	print body
	
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
	return

def checkout():
	'''
		# TODO: Accept the DID.
		Send request to server with required parameters (action = 'checkout') using post_request()
	'''
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
	return

def delete():
	'''
		# TODO: Accept the DID to be deleted.
		Send request to server with required parameters (action = 'delete')
		using post_request().
	'''
	return

def logout():
	'''
		# TODO: Ensure all the modified checked out documents are checked back in.
		Send request to server with required parameters (action = 'logout') using post_request()
		The request body should contain the user-id, session-token
	'''
	exit() #exit the program

def main():
	login()
	f = open(gt_username,"r")
	jsonfile=json.load(f)
	print jsonfile["status"]
	if jsonfile["status"]!=200: 
		exit()
	option=''
	while (option != '5' and jsonfile["status"]==200):
		option=raw_input('''Enter the option's number: 
				1. Checkin
				2. Checkout
				3. Grant
				4. Delete
				5. Logout \n
				\n
		''')
		if option=='1': login()
		if option=='2': checkin()

	
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


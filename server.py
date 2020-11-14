from flask import Flask, request, jsonify
from flask_restful import Resource, Api
# TODO: import additional modules as required
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import json
import base64
from uuid import uuid4

secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)

class welcome(Resource):
	def get(self):
		return "Welcome to the secure shared server!"

class login(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement login functionality
		body=json.loads(data)
		print body
		statement = body["statement"]
		
		# TODO: Verify the signed statement.
		# 	Response format for success and failure are given below. The same
		# 	keys ('status', 'message', 'session_token') should be used.
		keyaddr="userpublickeys/user"+body["userId"]+".pub"
		key = RSA.importKey(open(keyaddr,'r'))
		h = SHA256.new(str(statement))
		signature=base64.standard_b64decode((body["signature"]).encode("utf-8"))
		success=1
		#must ensure user ID unique
		try:
			pkcs1_15.new(key).verify(h, signature)
			print "The signature is valid."
		except (ValueError, TypeError):
			print "The signature is not valid."
			success=0

		
		if success:
			session_token = uuid4() # TODO: Generate session token
			# Similar response format given below can be used for all the other functions
			response = {
				'status': 200,
				'message': 'Login Successful',
				'session_token': session_token,
			}
		else:
			response = {
				'status': 700,
				'message': 'Login Failed'
			}
		return jsonify(response)

class checkout(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement checkout functionality
		return jsonify(response)
        '''
		Expected response status codes
		1) 200 - Document Successfully checked out
		2) 702 - Access denied to check out
		3) 703 - Check out failed due to broken integrity
		4) 704 - Check out failed since file not found on the server
		5) 700 - Other failures
        '''

class checkin(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement checkin functionality
		return jsonify(response)
        '''
		Expected response status codes:
		1) 200 - Document Successfully checked in
		2) 702 - Access denied to check in
		3) 700 - Other failures
	'''

class grant(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement grant functionality
		return jsonify(response)
	'''
		Expected response status codes:
		1) 200 - Successfully granted access
		2) 702 - Access denied to grant access
		3) 700 - Other failures
	'''

class delete(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement delete functionality
		return jsonify(response)
	'''
		Expected response status codes:
		1) 200 - Successfully deleted the file
		2) 702 - Access denied to delete file
		3) 704 - Delete failed since file not found on the server
		4) 700 - Other failures
	'''

class logout(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement logout functionality
		return jsonify(response)
	'''
		Expected response status codes:
		1) 200 - Successfully logged out
		2) 700 - Failed to log out
	'''

api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')

def main():
	secure_shared_service.run(debug=True)

if __name__ == '__main__':
	main()

#testing v2 testing again!!
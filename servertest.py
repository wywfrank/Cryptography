from flask import Flask, request, jsonify
from flask_restful import Resource, Api
# TODO: import additional modules as required
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import json
import base64
from uuid import uuid4
import sqlite3
# from sqlite3 import Error
import os
from flask import Flask, request, redirect, url_for, send_from_directory
from werkzeug import secure_filename


secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)

UPLOAD_FOLDER = 'documents'
secure_shared_service.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db=r"pythonsqlite.db"



def insert_owner(conn,row):
	sql='''INSERT INTO OWNER(did,userId,flag,encrypted_key)
		VALUES(?,?,?,?)'''
	cur=conn.cursor()
	cur.execute(sql,row)
	conn.commit()
	return 

def search_owner(conn,param):
	sql='''SELECT did FROM OWNER WHERE userId!=? AND did=?
		'''
	cur=conn.cursor()
	cur.execute(sql,param)
	result=cur.fetchone()
	conn.commit()
	print result
	return result

def insert_session(conn,row):
	sql='''DELETE FROM SESSION
		WHERE userId = ?'''
	cur=conn.cursor()
	cur.execute(sql,(row[1],))
	sql='''INSERT INTO SESSION(session_token,userId)
		VALUES(?,?)'''
	cur.execute(sql,row)
	conn.commit()
	return 


def search_session(conn,session_token):
	sql='''SELECT userId FROM SESSION WHERE session_token=?
		'''
	cur=conn.cursor()
	cur.execute(sql,session_token)
	userId=cur.fetchone()[0]
	conn.commit()
	return userId


class welcome(Resource):
	def get(self):
		return "Welcome to the secure shared server!"

class checkin(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement checkin functionality
		body=json.loads(data)
		conn=create_connection(db)
		session_token=str(body["session_token"])
		userId=search_session(conn,(session_token,))
		print "userId "+userId
		did=search_owner(conn,(userId,body["did"]))

		if did is None:
			if body["flag"]=='1':
				key = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
				print 'key', [x for x in key]
				iv = ''.join([chr(random.randint(0, 0xFF)) for i in range(16)])
				encryptor = AES.new(key, AES.MODE_CBC, iv)
				data=body["contents"].encode('utf-8')
				l=len(data)
				
				encd= encryptor.encrypt(data)
				decd= adec.decrypt(encd)
				# print str(decd)
			row=(body["did"],userId,body["flag"],"testing_key")
			insert_owner(conn,row)
				
			f = open("documents/"+body["did"],"w")
			print body["contents"]
			f.write(body["contents"])
			f.close()
			print "Done checkin"
			response= {
				'status': 200,
				'message': 'File Write Successful',
				'session_token': session_token,
			}
		else:
			response= {
				'status': 702,
				'message': 'Access Denied to check in',
				'session_token': session_token,
			}
		#need to add logic to allow authorized users to update document
		return jsonify(response)
        '''
		Expected response status codes:
		1) 200 - Document Successfully checked in
		2) 702 - Access denied to check in
		3) 700 - Other failures
		'''

class login(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement login functionality
		body=json.loads(data)
		statement = body["statement"]
		# TODO: Verify the signed statement.
		# 	Response format for success and failure are given below. The same
		# 	keys ('status', 'message', 'session_token') should be used.
		keyaddr="userpublickeys/user"+body["userId"]+".pub"
		key = RSA.importKey(open(keyaddr,'r'))
		h = SHA256.new(str(statement))
		signature=base64.standard_b64decode((body["signature"]).encode("utf-8"))
		success=1
		#must ensure user ID unique!!!
		try:
			pkcs1_15.new(key).verify(h, signature)
			print "The signature is valid."
		except (ValueError, TypeError):
			print "The signature is not valid."
			success=0
		
		if success:
			session_token = uuid4() # TODO: Generate session token
			# Similar response format given below can be used for all the other functions
			conn=create_connection(db)
			insert_session(conn,(str(session_token),str(body["userId"])))
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

class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]

def create_connection(db_file):
	conn = None
	try:
		conn=sqlite3.connect(db_file)
		return conn
	except Error as e:
		print e
	return conn
	# finally:
	# 	if conn:
	# 		conn.close()

def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print e


def main():
	sql_create_OWNER_table = '''
		CREATE TABLE IF NOT EXISTS OWNER 
		(did text NOT NULL,
		userId text NOT NULL,
		flag integer NOT NULL,
		encrypted_key text);
	'''
	sql_create_GRANT_table = '''
		CREATE TABLE IF NOT EXISTS GRANT 
		(did text NOT NULL,
		userId text NOT NULL,
		accessRight integer NOT NULL,
		time integer,
		created_date datetime);
	'''
	sql_create_SESSION_table = '''
		CREATE TABLE IF NOT EXISTS SESSION 
		(session_token text NOT NULL,
		userId text NOT NULL,
		timer text);
	'''
	conn = create_connection(db)
	if conn is not None:
		create_table(conn, sql_create_OWNER_table)
		create_table(conn, sql_create_GRANT_table)
		create_table(conn, sql_create_SESSION_table)
		conn.close()
	else:
		print("Error! Cannot create the database connection.")

	secure_shared_service.run(debug=True)


if __name__ == '__main__':
	main()
import datetime
import random
import json
import base64 
from uuid import uuid4
import sqlite3
from sqlite3 import Error
import os
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
# TODO: import additional modules as required
from flask import Flask, request, jsonify
from flask_restful import Resource, Api


secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)

UPLOAD_FOLDER = 'documents'
secure_shared_service.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db=r"pythonsqlite.db"



def insert_owner(conn,row):
	sql='''INSERT INTO OWNER(did,userId,flag)
		VALUES(?,?,?)'''
	cur=conn.cursor()
	cur.execute(sql,row)
	conn.commit()
	return 


def search_owner(conn,param):
	sql='''SELECT userId,flag FROM OWNER WHERE did=?
		'''
	cur=conn.cursor()
	cur.execute(sql,param)
	result=cur.fetchone()
	return result

def insert_session(conn,row):
	sql='''DELETE FROM SESSION
		WHERE userId = ?'''
	cur=conn.cursor()
	cur.execute(sql,(row[1],))
	conn.commit()
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
	result=cur.fetchone()
	if result is not None:
		result=result[0]
	return result


def insert_grant(conn,body):
	sql='''DELETE FROM GRANT
		WHERE CAST(strftime('%s', expire_date) AS integer) < CAST(strftime('%s', ?) AS integer) '''
	cur=conn.cursor()
	cur.execute(sql,(datetime.datetime.now(),))
	conn.commit()

	sql='''INSERT INTO GRANT(did,userId,accessRight,expire_date,created_date)
		VALUES(?,?,?,?,?)'''
	expire_date = datetime.datetime.now() + datetime.timedelta(seconds=int(body["expire_date"]))
	cur.execute(sql,(body["did"],body["userId"],body["accessRight"],expire_date,datetime.datetime.now()))
	conn.commit()
	return 

def search_grant(conn,body,userId,accessRight):
	sql='''DELETE FROM GRANT
		WHERE CAST(strftime('%s', expire_date) AS integer)<CAST(strftime('%s', ?) AS integer)'''
	cur=conn.cursor()
	cur.execute(sql,(datetime.datetime.now(),))
	conn.commit()

	sql='''Select accessRight from GRANT where (userId=0 or userId =?) and (accessRight=3 or accessRight=?) and did=?  
		order by created_date desc'''
	cur.execute(sql,(userId,accessRight,body["did"]))
	conn.commit()
	result=cur.fetchone()
	if result is not None:
		result=result[0]
	return result


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
		if userId is None:
			response= {
				'status': 700,
				'message': 'Unable to find session Id',
				'session_token': session_token,
			}
			print response
			return jsonify(response)
		userId=str(userId)
		if ((body["flag"]) not in ['1','2']) :
			response= {
				'status': 700,
				'message': 'Bad Flag number',
				'session_token': session_token,
			}
			print response
			return jsonify(response)
		
		did=search_owner(conn,(body["did"],))
		if did is None: #create new did entry if did doesn't exist
			row=(body["did"],userId,body["flag"])
			insert_owner(conn,row)
		
		ownerId,flag=search_owner(conn,(body["did"],))
		if str(flag)!=str(body["flag"]):
			response= {
				'status': 700,
				'message': 'Cannot check in same document with different flag',
				'session_token': session_token,
			}
			print response
			return jsonify(response)

		contents=str(body["contents"]) 
		encrypted_key = ''

		grantId=search_grant(conn,body,userId,1)
		if ownerId == userId or grantId is not None or str(grantId)=='1':
			if body["flag"]=='1':
				key = ''.join(chr(random.randint(0, 9)) for i in range(16))
				iv = ''.join([chr(random.randint(0, 9)) for i in range(16)])
				encryptor = AES.new(key, AES.MODE_CBC, iv)
				num_bytes_to_pad = AES.block_size - len(contents) % AES.block_size
				padded=contents+num_bytes_to_pad*(chr(num_bytes_to_pad))
				encrypted= encryptor.encrypt(padded.encode("utf-8"))
				encrypted_contents=base64.b64encode(iv+encrypted).decode("utf-8")
				contents=encrypted_contents
				
				keyPub=RSA.importKey(open('../certs/secure-shared-store.pub').read())
				cipher=PKCS1_OAEP.new(keyPub)
				encrypted_key=cipher.encrypt(key)
				f = open("documents/key-"+body["did"].split('.')[0]+body["did"].split('.')[1],"w")
				f.write(encrypted_key)
				f.close()

			if body["flag"]=='2':
				keyPri=RSA.importKey(open('../certs/secure-shared-store.key').read())
				h = SHA256.new(contents)
				signature = pkcs1_15.new(keyPri).sign(h)
				f = open("documents/signed-"+body["did"].split('.')[0]+body["did"].split('.')[1],"w")
				f.write(signature)
				f.close()
			
			
			f = open("documents/"+body["did"],"w")
			f.write(contents)
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
		try:
			key = RSA.importKey(open(keyaddr,'r'))
		except IOError:
			response = {
				'status': 700,
				'message': 'Key does not exist on server.',
			}
			return jsonify(response)
		
		h = SHA256.new(str(statement))
		signature=base64.standard_b64decode((body["signature"]).encode("utf-8"))

		#must ensure user ID unique!!!
		try:
			pkcs1_15.new(key).verify(h, signature)
		except (ValueError, TypeError):
			response = {
				'status': 700,
				'message': 'Key does not match.',
			}
			return jsonify(response)
		
		session_token = uuid4() # TODO: Generate session token
		# Similar response format given below can be used for all the other functions
		conn=create_connection(db)
		insert_session(conn,(str(session_token),str(body["userId"])))
		response = {
			'status': 200,
			'message': 'Login Successful',
			'session_token': session_token,
		}
		return jsonify(response)

class checkout(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement checkout functionality
		
		conn=create_connection(db)
		body=json.loads(data)
		ownerId=search_owner(conn,(body["did"],))
		session_token=str(body["session_token"])
		flag=''
		if ownerId is not None:
			ownerId,flag=ownerId[0],ownerId[1]
		else:
			response = {
				'status': 700,
				'message': 'Other failures',
				'session_token': session_token,
			}
			return jsonify(response) 

		userId=search_session(conn,(session_token,))
		response=''

		if os.path.exists('documents/'+body["did"])==False:
			response = {
				'status': 704,
				'message': 'Check out failed since file not found on the server',
				'session_token': session_token,
			}
			return jsonify(response)
		grantId=search_grant(conn,body,userId,2)
		if ownerId != userId and (grantId is None or str(grantId)=='2'):
			response = {
				'status': 702,
				'message': 'Access denied to check out',
				'session_token': session_token,
			}
			return jsonify(response)
		contents=open('documents/'+body["did"]).read()
		response = {
			'status': 700,
			'message': 'Other failures',
			'session_token': session_token,
		}
		if flag==1:
			encrypted_key= open("documents/key-"+body["did"].split('.')[0]+body["did"].split('.')[1]).read()
			keyPri=RSA.importKey(open('../certs/secure-shared-store.key').read())
			cipher = PKCS1_OAEP.new(keyPri)
			key = cipher.decrypt(encrypted_key)
			encrypted_decoded=base64.b64decode(contents)
			iv=encrypted_decoded[:AES.block_size]
			decryptor=AES.new(key,AES.MODE_CBC, iv)
			plain_text = decryptor.decrypt(encrypted_decoded[AES.block_size:]).decode("utf-8")
			last_character = plain_text[len(plain_text) - 1:]
			original_contents= plain_text[:-ord(last_character)]
			response = {
				'status': 200,
				'did': body["did"],
				'message': 'Document Successfully checked out',
				'contents': original_contents,
				'session_token': session_token,
			}
		if flag==2:
			keyPub = RSA.import_key(open('../certs/secure-shared-store.pub').read())
			h = SHA256.new(contents)
			signature=open("documents/signed-"+body["did"].split('.')[0]+body["did"].split('.')[1]).read()
			try:
				pkcs1_15.new(keyPub).verify(h, signature)
				response = {
					'status': 200,
					'did': body["did"],
					'message': 'Document Successfully checked out',
					'contents': contents,
					'session_token': session_token,
				}
			except (ValueError, TypeError):
				print "The signature is not valid."
				response = {
					'status': 703,
					'message': 'Check out failed due to broken integrity',
					'session_token': session_token,
				}
			
		return jsonify(response)



class grant(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement grant functionality
		conn=create_connection(db)
		body=json.loads(data)
		session_token=str(body["session_token"])
		
		userId=search_session(conn,(session_token,))

		if userId is None:
			response= {
				'status': 700,
				'message': 'Unable to find session Id',
				'session_token': session_token,
			}
			print response
			return jsonify(response)

		userId=str(userId)
		ownerId=search_owner(conn,(str(body["did"]),))
		if ownerId is None:
			response= {
				'status': 700,
				'message': 'Unable to find document or owner',
				'session_token': session_token,
			}
			return jsonify(response)
		ownerId=ownerId[0]
		if ownerId != userId:
			response= {
				'status': 702,
				'message': 'Access denied to grant access',
				'session_token': session_token,
			}
			return jsonify(response)

		insert_grant(conn,body)
		response={
			'status': 200,
			'message': 'Successfully granted access',
			'session_token': session_token,
		}
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
		body=json.loads(data)
		session_token=str(body["session_token"])
		
		conn=create_connection(db)
		userId=search_session(conn,(session_token,))
		if userId is None:
			response= {
				'status': 700,
				'message': 'Unable to find session Id',
				'session_token': session_token,
			}
			return jsonify(response)

		userId=str(userId)
		ownerId=search_owner(conn,(str(body["did"]),))
		if ownerId is None:
			response= {
				'status': 700,
				'message': 'Delete failed since file not found on the server',
				'session_token': session_token,
			}
			return jsonify(response)
		ownerId=ownerId[0]

		if ownerId != userId:
			response= {
				'status': 702,
				'message': 'Access denied to delete file',
				'session_token': session_token,
			}
			return jsonify(response)
		
		sql='''DELETE FROM OWNER
		WHERE did = ?'''
		cur=conn.cursor()
		cur.execute(sql,(str(body["did"]),))
		conn.commit()
		sql='''DELETE FROM GRANT
		WHERE did = ?'''
		cur.execute(sql,(str(body["did"]),))
		conn.commit()
		conn.close()

		if os.path.exists("documents/"+body["did"]): 
			os.remove("documents/"+body["did"]) 
		else:
			response= {
				'status': 704,
				'message': 'Delete failed since file not found on the server',
				'session_token': session_token,
			}
			return jsonify(response)

		if os.path.exists("documents/key-"+body["did"].split('.')[0]+body["did"].split('.')[1]):
			os.remove("documents/key-"+body["did"].split('.')[0]+body["did"].split('.')[1])
		if os.path.exists("documents/signed-"+body["did"].split('.')[0]+body["did"].split('.')[1]):
			os.remove("documents/signed-"+body["did"].split('.')[0]+body["did"].split('.')[1])
		
		response= {
				'status': 200,
				'message': 'Successfully deleted the file',
				'session_token': session_token,
			}
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
		conn=create_connection(db)
		body=json.loads(data)
		session_token=str(body["session_token"])
		userId=search_session(conn,(session_token,))
		if userId is None:
			response= {
				'status': 700,
				'message': 'Failed to log out',
				'session_token': session_token,
			}
			return jsonify(response)

		sql='''DELETE FROM SESSION
		WHERE userId= ?'''
		cur=conn.cursor()
		cur.execute(sql,(str(userId),))
		conn.commit()
		conn.close()
		response= {
				'status': 200,
				'message': 'Successfully logged out',
			}
		return jsonify(response)
api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')

def create_connection(db_file):
	conn = None
	try:
		conn=sqlite3.connect(db_file)
		return conn
	except Error as e:
		print e
	return conn

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
		flag integer NOT NULL);
	'''
	sql_create_GRANT_table = '''
		CREATE TABLE IF NOT EXISTS GRANT 
		(did text NOT NULL,
		userId text NOT NULL,
		accessRight integer NOT NULL,
		expire_date datetime NOT NULL,
		created_date datetime NOT NULL);
	'''
	sql_create_SESSION_table = '''
		CREATE TABLE IF NOT EXISTS SESSION 
		(session_token text NOT NULL,
		userId text NOT NULL);
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

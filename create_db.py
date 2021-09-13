import mysql.connector

# Establish a connection
mydb = mysql.connector.connect(host='localhost',
	user='root',
	passwd = 'july2021_'
	)

# Creates a Cursor robot
my_cursor = mydb.cursor()

# Creates a DB
# Commented it out not to create our_users DB again
my_cursor.execute("CREATE DATABASE our_users")

# Print a database
my_cursor.execute("SHOW DATABASES")
for db in my_cursor:
	print(db)
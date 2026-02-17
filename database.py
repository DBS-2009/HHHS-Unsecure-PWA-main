import sqlite3

connection = sqlite3.Connection('LoginData.db')
cursor = connection.cursor() 

cmd1 = """ CREATE TABLE IF NOT EXISTS USERS(first_name varchar(50),
                                        last_name varchar(50),
                                        email varchar(50) primary key,
                                        password varchar(50) not null) """
cursor.execute(cmd1)

cmd2 = """INSERT INTO USERS (first_name, last_name, email, password) values('tester','test','tester@gmail.com','testerP')"""
cursor.execute(cmd2)
connection.commit()

ans = cursor.execute("select * from USERS").fetchall()

for i in ans:
    print(i) 
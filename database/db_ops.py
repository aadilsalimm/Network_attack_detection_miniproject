import sqlite3

def db_connect():
    """ Initiates database connection. Returns a cursor."""
    connection =  sqlite3.connect('database/db/log.db')
    return connection.cursor()


if __name__ == "__main__":
    db_connect()
    print("success")
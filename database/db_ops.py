import sqlite3

db_connection = None
db_cursor = None

def db_connect():
    global db_connection 
    global db_cursor
    db_connection = sqlite3.connect('database/db/log.db', check_same_thread=False)
    db_cursor = db_connection.cursor()



def add_data(mal_ips,timestamps):
    for timestamp, ip in zip(timestamps, mal_ips):
        db_cursor.execute(f'''INSERT INTO log VALUES ('{timestamp}', '{ip}')''')
        db_connection.commit()


def del_data(ip):
    db_cursor.execute(f'''DELETE FROM log WHERE ip = '{ip}' ''')
    db_connection.commit()


def get_blocked_ips():
    blocked = db_cursor.execute(f'''SELECT ip FROM log''')
    output = db_cursor.fetchall()
    replacements = str.maketrans({"(": "", "'": "", ")": "", ",": "" })
    blocked_ips = []
    for op in output:
        blocked_ips.append(str(op).translate(replacements))

    return blocked_ips


def close_db_connection():
    db_connection.close()


if __name__ == "__main__":
    db_connect()
    #cursor = connection.cursor()
    del_data('15.16.17.18')
    db_connection.commit()
    db_connection.close()
    print("success")
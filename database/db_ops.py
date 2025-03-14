import sqlite3

def db_connect():
    return sqlite3.connect('database/db/log.db', check_same_thread=False)


def add_data(db,mal_ips,timestamps):
    for timestamp, ip in zip(timestamps, mal_ips):
        db.execute(f'''INSERT INTO log VALUES ('{timestamp}', '{ip}')''')


def del_data(db,ip):
    db.execute(f'''DELETE FROM log WHERE ip = '{ip}' ''')


if __name__ == "__main__":
    connection = db_connect()
    cursor = connection.cursor()
    del_data(cursor, '15.16.17.18')
    connection.commit()
    connection.close()
    print("success")
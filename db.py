# db.py
import mysql.connector
from mysql.connector import Error
from config import Config

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=Config.DB_HOST,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
            port=Config.DB_PORT,
            charset="utf8mb4"
        )
        return connection
    except Error as e:
        print(f"DB connection failed: {e}")
        return None

def get_cursor(connection, dictionary=True):
    return connection.cursor(dictionary=dictionary)


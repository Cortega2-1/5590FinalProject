import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "secureeval.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS users (
                                                        id       INTEGER PRIMARY KEY AUTOINCREMENT,
                                                        username TEXT    UNIQUE NOT NULL,
                                                        password TEXT    NOT NULL
                   )
                   """)
    conn.commit()
    conn.close()
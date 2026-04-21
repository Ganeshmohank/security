"""Vulnerable DB helpers (fixture)."""

import hashlib
import sqlite3


DB_USER = "admin"
DB_PASSWORD = "password123"


def open_conn():
    return sqlite3.connect("app.db")


def insert_account(user_name, raw_pwd):
    conn = open_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password) VALUES ('{}', '{}')".format(
            user_name, raw_pwd
        )
    )
    conn.commit()
    conn.close()


def fetch_account(account_id):
    conn = open_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s" % account_id)
    row = cur.fetchone()
    conn.close()
    return row


def delete_account_by_name(user_name):
    conn = open_conn()
    cur = conn.cursor()
    sql = f"DELETE FROM users WHERE username = '{user_name}'"
    cur.execute(sql)
    conn.commit()
    conn.close()


def digest(raw):
    return hashlib.md5(raw.encode()).hexdigest()


def verify(raw, digest_value):
    return hashlib.sha1(raw.encode()).hexdigest() == digest_value

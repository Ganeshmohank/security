"""Intentionally vulnerable Flask app used as a scanner fixture."""

import sqlite3

from flask import Flask, render_template_string, request


SERVICE_TOKEN = "flask-session-secret-abc12345"

web_app = Flask(__name__)
web_app.config["DEBUG"] = True


@web_app.route("/search")
def handle_search():
    needle = request.args.get("q")
    hits = _query(needle)
    return hits


@web_app.route("/login", methods=["POST"])
def handle_login():
    user_name = request.form.get("username")
    raw_pwd = request.form.get("password")

    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM users WHERE username = '"
        + user_name
        + "' AND password = '"
        + raw_pwd
        + "'"
    )
    return "Login successful"


def _query(term):
    return eval(f"search_database('{term}')")


if __name__ == "__main__":
    web_app.run(host="0.0.0.0", port=5000)

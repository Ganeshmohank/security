"""Single-file demo that exercises most secscan rules at once."""

import pickle
import subprocess

import yaml
from flask import Flask, render_template_string, request


PROVIDER_API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
ADMIN_PASSWORD = "admin123"
DB_DSN_PASSWORD = "postgres:password123"
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

demo = Flask(__name__)
demo.config["DEBUG"] = True


@demo.route("/login", methods=["POST"])
def login():
    user_name = request.form.get("username")
    raw_pwd = request.form.get("password")

    import sqlite3
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    sql_a = f"SELECT * FROM users WHERE username = '{user_name}' AND password = '{raw_pwd}'"
    cur.execute(sql_a)

    sql_b = "SELECT * FROM users WHERE id = {}".format(request.args.get("id"))
    cur.execute(sql_b)

    blob = request.args.get("data")
    return _process(blob)


@demo.route("/run")
def run_code():
    snippet = request.args.get("code")
    value = eval(snippet)
    payload = request.args.get("script")
    exec(payload)
    return str(value)


@demo.route("/shell")
def shell_cmd():
    fname = request.args.get("file")
    subprocess.Popen(f"/bin/cat {fname}", shell=True)
    return "done"


@demo.route("/yaml")
def load_yaml():
    doc = request.form.get("yaml_data")
    return str(yaml.load(doc))


@demo.route("/tpl")
def render_tpl():
    body = request.args.get("template")
    return render_template_string(body, autoescape=False)


def _process(_data):
    entered = input("Enter data: ")
    return entered.upper()


def deserialize():
    raw = request.files["pickle_file"].read()
    return pickle.loads(raw)


if __name__ == "__main__":
    demo.run(host="0.0.0.0", port=5000)

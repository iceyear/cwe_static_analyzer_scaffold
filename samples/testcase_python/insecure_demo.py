import hashlib
import os
import pickle
import random
import requests
import sqlite3
import subprocess
import yaml

API_KEY = "demo-api-key-123456"


def handler(user_input, blob, url):
    os.system("ping " + user_input)
    subprocess.run("cat " + user_input, shell=True)
    eval(user_input)
    pickle.loads(blob)
    yaml.load(blob)
    hashlib.md5(user_input.encode()).hexdigest()
    token = random.randint(100000, 999999)
    requests.get(url, verify=False)

    con = sqlite3.connect(":memory:")
    cur = con.cursor()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cur.execute(query)
    return token


if __name__ == "__main__":
    app.run(debug=True)

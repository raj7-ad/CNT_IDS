# simple low-rate brute-force simulator against /login
import os, time, requests

TARGET = os.environ.get("TARGET","http://nginx")
WORDS = ["admin:1234","test:password","user:letmein"]
INTERVAL = float(os.environ.get("INTERVAL","1.0"))

def attempt(user, pwd):
    try:
        r = requests.post(TARGET + "/login", data={"username": user, "password": pwd}, timeout=5)
        print(time.ctime(), r.status_code, user, pwd)
    except Exception as e:
        print(time.ctime(), "ERR", e)

while True:
    for up in WORDS:
        user,pwd = up.split(":",1)
        attempt(user,pwd)
        time.sleep(INTERVAL)

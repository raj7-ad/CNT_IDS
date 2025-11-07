import autogen, time, os, csv, subprocess, json
from collections import defaultdict
import docker

AUTO_APPLY = os.environ.get('AUTO_APPLY_BLOCKS','false').lower() in ('1','true','yes')
BAD_IPS_CSV = '/var/bad_ips.csv'
NGINX_CONTAINER_NAME = 'nginx'

def append_bad_ip(ip, reason, ttl=300):
    expiry = int(time.time()) + ttl
    line = f"{ip},{expiry},{reason}\n"
    # write to shared CSV (append)
    try:
        with open(BAD_IPS_CSV, 'a') as f:
            f.write(line)
        print('Appended bad ip', line.strip())
    except Exception as e:
        print('Failed to append bad ip', e)
    if AUTO_APPLY:
        # call update_proxy.py if allowed
        try:
            subprocess.run(['python3','/usr/src/app/autogen/scripts/update_proxy.py'], check=False)
        except Exception as e:
            print('Failed to run update_proxy.py', e)

def detect_bruteforce_from_web(logpath='/var/log/nginx/access.log', window=300, threshold=5):
    # Count repeated POST /login with 401 from same IP
    counts = defaultdict(int)
    try:
        with open(logpath,'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 9: continue
                ip = parts[0]
                method = parts[5].strip('"')
                path = parts[6]
                status = parts[8]
                if method=='POST' and path.startswith('/login') and status=='401':
                    counts[ip]+=1
        for ip,c in counts.items():
            if c >= threshold:
                print('Detected brute-force from', ip, 'count', c)
                append_bad_ip(ip, 'bruteforce', ttl=600)
    except FileNotFoundError:
        print('nginx access log not found at', logpath)
    except Exception as e:
        print('bruteforce detector error', e)

def detect_dns_tunnel(logpath='/var/log/dns_queries.log', window=300, threshold=10):
    # Look for many DNS queries with high-entropy subdomains from same IP
    # Here dns server logs are written to stdout; we will expect a mounted log file
    counts = defaultdict(int)
    try:
        with open(logpath,'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 5: continue
                ip = parts[3]
                qname = parts[4]
                # simple entropy heuristic: long label or base64-like chars
                if len(str(qname)) > 30 or any(c in str(qname) for c in ('=','/','+')):
                    counts[ip]+=1
        for ip,c in counts.items():
            if c >= threshold:
                print('Detected possible DNS tunneling from', ip, 'count', c)
                append_bad_ip(ip, 'dns_tunnel', ttl=600)
    except FileNotFoundError:
        print('dns log not found at', logpath)
    except Exception as e:
        print('dns detect error', e)

def detect_portscan_and_syn(nginx_container_name=NGINX_CONTAINER_NAME, portscan_threshold=20, syn_threshold=50):
    # Use docker SDK to exec ss inside nginx container to inspect connections (best-effort)
    try:
        client = docker.from_env()
        c = client.containers.get(nginx_container_name)
        out = c.exec_run("ss -tan state syn-recv", stdout=True, stderr=True)
        text = out.output.decode() if hasattr(out, 'output') else out.decode()
        # Count occurrences per src ip (very simple parse)
        counts = defaultdict(int)
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 5: continue
            # line might contain src:port->dst:port; crude parse for src ip
            if '->' in line:
                try:
                    left = line.split('->')[0]
                    src = left.split()[-1].rsplit(':',1)[0]
                    counts[src]+=1
                except Exception:
                    pass
        for ip,c in counts.items():
            if c >= portscan_threshold:
                print('Detected possible portscan from', ip, 'count', c)
                append_bad_ip(ip, 'portscan', ttl=600)
            if c >= syn_threshold:
                print('Detected possible syn flood from', ip, 'count', c)
                append_bad_ip(ip, 'syn_flood', ttl=600)
    except Exception as e:
        print('portscan/syn detector error', e)

if __name__ == '__main__':
    print('Agent starting detection loop (safe defaults). AUTO_APPLY=', AUTO_APPLY)
    while True:
        try:
            detect_bruteforce_from_web()
            detect_dns_tunnel(logpath='/var/log/dns_queries.log')
            detect_portscan_and_syn()
        except Exception as e:
            print('Main loop error', e)
        time.sleep(10)

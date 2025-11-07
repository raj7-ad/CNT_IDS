import csv, time, os, docker
CSV = '/var/bad_ips.csv'
NGINX_BLOCK_FILE = '/etc/nginx/conf.d/blocked.conf'
PLACEHOLDER = '# DENY_IPs'

def read_bad_ips():
    ips = []
    try:
        with open(CSV,'r') as f:
            for row in csv.reader(f):
                if not row: continue
                ip = row[0].strip()
                if not ip: continue
                # handle expiry if present
                if len(row) > 1:
                    try:
                        expiry = int(row[1])
                        if time.time() > expiry:
                            continue
                    except:
                        pass
                ips.append(ip)
    except FileNotFoundError:
        print('no bad ips file yet')
    return ips

def write_block_file(ips):
    lines = [f'deny {ip};' for ip in ips]
    body = '\n'.join(lines) + '\n'
    try:
        with open(NGINX_BLOCK_FILE,'w') as f:
            f.write(body)
        print('Wrote', NGINX_BLOCK_FILE)
    except Exception as e:
        print('Failed to write block file', e)

if __name__ == '__main__':
    ips = read_bad_ips()
    write_block_file(ips)
    # reload nginx container if present
    try:
        client = docker.from_env()
        c = client.containers.get('nginx')
        c.exec_run('nginx -s reload')
        print('Reloaded nginx')
    except Exception as e:
        print('Could not reload nginx', e)

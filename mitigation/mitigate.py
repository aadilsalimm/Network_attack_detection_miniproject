import os

def block_ip(mal_ips):
    for ip in mal_ips:
        os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')
        print(f'{ip} blocked.')


def unblock_ip(ip):
    os.system(f'sudo iptables -D INPUT -s {ip} -j DROP')
    print(f'{ip} unblocked.')        
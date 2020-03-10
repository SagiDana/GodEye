from netifaces import interfaces, ifaddresses, AF_INET
import subprocess
import psutil
import re 


def execute_command(cmd, *args):
    try:
        command = cmd.format(*args)
        pipes = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        std_out, std_err = pipes.communicate()

        return std_out, std_err
    except Exception as e:
        print("Exception: {}".format(str(e)))
    return None, None

def get_local_ips():
    ip_list = []
    for interface in interfaces():
        try:
            for link in ifaddresses(interface)[AF_INET]:
                ip_list.append(link['addr'])
        except: continue
    return ip_list

def is_local_ip(ip):
    return ip in get_local_ips()

def get_process_from_connection(connection):
    process = None

    out, err = None, None
    out, err = execute_command("sudo netstat -antulp | grep {}:{} | grep {}:{}", connection[0], connection[2], connection[1], connection[3])

    match = re.search(r"\d+/(?P<process_name>.*)$", out.decode())
    if match:
        process = match.group('process_name').strip()
        return process

    return "pid: -1"

if __name__=="__main__":
    get_process_from_connection(None)

from netifaces import interfaces, ifaddresses, AF_INET
import subprocess
import psutil
import re 


def execute_command(cmd, *args):
    try:
        command = cmd.format(*args)
        pipes = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        std_out, std_err = pipes.communicate()

        # if len(std_err) == 0:
        #     print("Command: {} | Stdout: {}".format(command, std_out))
        #
        # if len(std_err) > 0:
        #     print("Command: {} | Stderr: {}".format(command, std_err))
        return std_out, std_err

    except Exception as e:
        print("Exception: {}".format(str(e)))
        pass
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
    pid = None
    process = None
    for conn in psutil.net_connections("all"):
        # print("conn: {}".format(conn))
        try:
            # if conn.status != 'ESTABLISHED':
            #     continue

            lAddr = conn.laddr[0]
            lPort = conn.laddr[1]
            rAddr = conn.raddr[0]
            rPort = conn.raddr[1]

            if lAddr not in connection[:2]:
                continue
            if rAddr not in connection[:2]:
                continue
            if lPort not in connection[2:]:
                continue
            if rPort not in connection[2:]:
                continue

            pid = conn.pid
        except: continue

    if not pid:
        out, err = None, None
        
        out, err = execute_command("sudo netstat -antulp | grep {}:{} | grep {}:{}", connection[0], connection[2], connection[1], connection[3])
        # if out != '':
        #     print(out)

        # if not is_local_ip(connection[0]):
        #     out, err = execute_command("sudo netstat -antulp | grep {}:{}", connection[0], connection[2])
        # elif not is_local_ip(connection[1]):
        #     out, err = execute_command("sudo netstat -antulp | grep {}:{}", connection[1], connection[3])

        match = re.search(r"\d+/(?P<process_name>.*)$", str(out))
        if match == None:
            return "pid: -1"
        else:
            return match.group('process_name').strip()

    for proc in psutil.process_iter():
        # print(proc)
        if proc.pid == pid:
            process = proc.name()

    if not process:
        return "pid: {}".format(pid)

    return process

if __name__=="__main__":
    get_process_from_connection(None)

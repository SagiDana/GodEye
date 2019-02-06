import win32service as ws
import ctypes
import struct
import socket
import os


def get_services(process_id):
    services_names = []

    hSCManager = ws.OpenSCManager(None, None, ws.SC_MANAGER_CONNECT | ws.SC_MANAGER_ENUMERATE_SERVICE)

    services = ws.EnumServicesStatusEx(hSCManager,
                            ws.SERVICE_WIN32,
                            ws.SERVICE_STATE_ALL,
                            None,
                            ws.SC_ENUM_PROCESS_INFO)

    for service in services:
        if service["ProcessId"] == process_id:
            services_names.append(service["ServiceName"])

    if len(services_names) == 0:
        return None

    services_names = sorted(services_names)

    return services_names

def get_process_from_connection(connection):
    pid = get_pid_from_connection(connection)
    process_name = get_process_name_by_id(pid)

    if "svchost" not in process_name.lower():
        return process_name

    services_names = get_services(pid)

    if not services_names:
        return process_name

    return services_names.join(',')

def get_pid_from_connection(connection):
    DWORD = ctypes.c_ulong
    NO_ERROR = 0
    NULL = ""
    bOrder = 0

    # define some MIB constants used to identify the state of a TCP port
    MIB_TCP_STATE_CLOSED = 1
    MIB_TCP_STATE_LISTEN = 2
    MIB_TCP_STATE_SYN_SENT = 3
    MIB_TCP_STATE_SYN_RCVD = 4
    MIB_TCP_STATE_ESTAB = 5
    MIB_TCP_STATE_FIN_WAIT1 = 6
    MIB_TCP_STATE_FIN_WAIT2 = 7
    MIB_TCP_STATE_CLOSE_WAIT = 8
    MIB_TCP_STATE_CLOSING = 9
    MIB_TCP_STATE_LAST_ACK = 10
    MIB_TCP_STATE_TIME_WAIT = 11
    MIB_TCP_STATE_DELETE_TCB = 12

    ANY_SIZE = 1

    # defing our MIB row structures
    class MIB_TCPROW2(ctypes.Structure):
        _fields_ = [('dwState', DWORD),
                    ('dwLocalAddr', DWORD),
                    ('dwLocalPort', DWORD),
                    ('dwRemoteAddr', DWORD),
                    ('dwRemotePort', DWORD),
                    ('dwOwningPid', DWORD),
                    ('dwOffloadState', DWORD)]

    dwSize = DWORD(0)

    GetTcpTable2 = ctypes.windll.iphlpapi.GetTcpTable2
    # call once to get dwSize
    GetTcpTable2(NULL, ctypes.byref(dwSize), bOrder)

    # ANY_SIZE is used out of convention (to be like MS docs); even setting this
    # to dwSize will likely be much larger than actually necessary but much
    # more efficient that just declaring ANY_SIZE = 65500.
    # (in C we would use malloc to allocate memory for the *table pointer and
    #  then have ANY_SIZE set to 1 in the structure definition)

    ANY_SIZE = dwSize.value

    class MIB_TCPTABLE2(ctypes.Structure):
        _fields_ = [('dwNumEntries', DWORD),
                    ('table', MIB_TCPROW2 * ANY_SIZE)]

    tcpTable = MIB_TCPTABLE2()
    tcpTable.dwNumEntries = 0 # define as 0 for our loops sake

    # now make the call to GetTcpTable to get the data
    if (GetTcpTable2(ctypes.byref(tcpTable),
        ctypes.byref(dwSize), bOrder) == NO_ERROR):

        maxNum = tcpTable.dwNumEntries
        placeHolder = 0

        # loop through every connection
        while placeHolder < maxNum:

            item = tcpTable.table[placeHolder]
            placeHolder += 1

            # format the data we need (there is more data if it is useful -
            #    see structure definition)
            lPort = socket.ntohs(item.dwLocalPort)
            lAddr = item.dwLocalAddr
            lAddr = socket.inet_ntoa(struct.pack('L', lAddr))
            rPort = socket.ntohs(item.dwRemotePort)
            rAddr = item.dwRemoteAddr
            rAddr = socket.inet_ntoa(struct.pack('L', rAddr))

            if lAddr not in connection[:2]:
                continue
            if rAddr not in connection[:2]:
                continue
            if lPort not in connection[2:]:
                continue
            if rPort not in connection[2:]:
                continue

            pid = item.dwOwningPid
            return pid
    else:
        print("Error occurred when trying to get TCP Table")

    return -1

def get_process_name_by_id(pid):
    process_name = (ctypes.c_char*255)()

    psapi = ctypes.WinDLL('Psapi.dll')
    OpenProcess = ctypes.windll.kernel32.OpenProcess
    GetProcessImageFileNameA = psapi.GetProcessImageFileNameA


    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

    if handle:
        if GetProcessImageFileNameA(handle, process_name, 255) > 0:
            return os.path.basename(process_name.value).decode()

    return "pid:{}".format(pid)

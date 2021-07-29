import json
import select

# NOT necessary?
def check_client_type(data):
    data = json.loads(data)
    if data["type"] == "web":
        return select.EPOLLIN # read
    elif data["type"] == "agent":
        return select.EPOLLOUT # write

def ip_to_fd(ip, connection_list):
    for conn_fd, conn_sckt in connection_list.items():
        if ip == conn_sckt.getpeername()[0]:
            return conn_fd
    return None

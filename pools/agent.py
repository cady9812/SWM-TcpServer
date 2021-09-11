import sys
from pathlib import Path
path = Path(__file__).parent.resolve()
parent = path.parents[0]
[sys.path.append(x) for x in map(str, [path, parent]) if x not in sys.path]

import bson
import socket
import log_config
from config import *
import utility

logger = log_config.get_custom_logger(__name__)


class AgentPool(object):
    def __init__(self):
        self.agents = {}

    def add(self, sock:socket.socket):
        fd = sock.fileno()
        ip = utility.get_ip_from_sock(sock)
        logger.info(f"{MAGENT}Welcome, New Agent {fd}:{ip}{END}")
        self.agents[fd] = sock

        data = {'ip': ip, 'id': fd}
        utility.http_request('/agent/add', 'POST', json=data)
        return

    def has(self, fd: int):
        return fd in self.agents

    def get(self, fd: int):
        assert self.has(fd)
        return self.agents[fd]

    def delete(self, fd: int):
        assert self.has(fd)

        sock = self.agents.pop(fd)
        ip = utility.get_ip_from_sock(sock)
        logger.info(f"{BLUE}Bye Agent {fd}:{ip}{END}")

        data = {'ip':ip, 'id': fd}
        utility.http_request('/agent/del', "POST", json=data)
        sock.close()

    def ip_of(self, fd: int):
        sock = self.agents[fd]
        ip = utility.get_ip_from_sock(sock)

        return ip

    def sock_of(self, ip: str):
        for fd in self.agents:
            sock = self.agents[fd]
            tmp_ip = utility.get_ip_from_sock(sock)
            if ip == tmp_ip:
                return sock
        
        logger.error(f"{RED}Failed to search {ip} in AgentPool{END}")
        return None

    def send_to(self, ip: str, contents):
        sock = self.sock_of(ip)
        data = bson.dumps(contents)
        sock.send(data)

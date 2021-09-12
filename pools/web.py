import sys
from pathlib import Path
path = Path(__file__).parent.resolve()
parent = path.parents[0]
[sys.path.append(x) for x in map(str, [path, parent]) if x not in sys.path]

import socket
import log_config
from config import *
import utility

logger = log_config.get_custom_logger(__name__)

class WebPool(object):
    def __init__(self):
        self.webs = {}

    def add(self, sock: socket.socket):
        fd = sock.fileno()
        ip = sock.getpeername()[0]
        logger.info(f"{CYAN}Hello Web, {fd}:{ip}{END}")
        self.webs[fd] = sock
        return

    def has(self, fd: int):
        return fd in self.webs

    def get(self, fd: int):
        assert self.has(fd)
        return self.webs[fd]

    def ip_of(self, fd: int):
        sock = self.agents[fd]
        ip = sock.getpeername()[0]

        return ip

    def delete(self, fd: int):
        assert self.has(fd)

        sock = self.webs.pop(fd)
        ip = utility.get_ip_from_sock(sock)
        logger.info(f"{GREEN}Bye Web{fd}:{ip}{END}")
        sock.close()
        return

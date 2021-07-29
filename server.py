import select
import socket
import json
from utilities import functions

class TcpServer(object):
    IP = "0.0.0.0"
    PORT = 8000
    BUFSIZE = 1024
    connection_list = {}

    def __init__(self):
        self._prepare_listening_socket()
        self._prepare_epoll()
        return

    def _prepare_listening_socket(self):
        sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sckt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sckt.bind((self.IP, self.PORT))
        sckt.listen(0)
        self.serverSocket = sckt
        return
    
    def _prepare_epoll(self):
        epoll = select.epoll()
        epoll.register(self.serverSocket.fileno(), select.EPOLLIN)

        self.epoll = epoll
        return
    def _process_commands(self, fd, recvData):
        src_fd = functions.ip_to_fd(recvData['ip'], self.connection_list)
        if src_fd == None:
            print('can\'t find fd from ip')
            return None
        src_socket = self.connection_list[src_fd]
        src_socket.send(json.dumps(recvData))
        return

    def _process_event(self, fd, event):
        conn_list = self.connection_list
        epoll = self.epoll
        serverSocket = self.serverSocket

        if fd == serverSocket.fileno():
            # new connection
            clientSocket, clientAddr = serverSocket.accept()
            recvData = clientSocket.recv(self.BUFSIZE)
            eventmask = functions.check_client_type(recvData)

            epoll.register(clientSocket.fileno(), eventmask)
            conn_list[clientSocket.fileno()]=clientSocket
            return
        elif event & select.EPOLLIN:
            recvData = serverSocket.recv(self.BUFSIZE)
            if not recvData:
                epoll.unregister(fd)
                conn_list.pop(fd).close()
                print(f"fd[{fd}] closed")
                return None
            recvData = json.loads(recvData).decode()
            self._process_commands(fd, recvData)
            return

    def poll_once(self):
        events = self.epoll.poll()
        if not events:
            print("Epoll timeout no active connection, re-polling...")
        for fd, event in events:
            self._process_event(fd, event)
        return

    def run(self):
        while True:
            self.poll_once()

if __name__=="__main__":
    s = TcpServer()
    s.run()

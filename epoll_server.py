import socket, select
import os
import bson
import logging
import requests
from multiprocessing import Process, Manager


### GLOBAL VARIABLE ###
HOST_IP = '0.0.0.0'
AGENT_PORT = 9000
WEB_PORT = 8000
WEB_URL = 'http://localhost:5000'

sEPOLL = select.epoll() # POLL for agent


def setupSocket():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(HOST_IP, AGENT_PORT)
    server_socket.listen(1)

    return server_socket

class TCP_Server:
    def __init__(self,fd, _):
        self.temp_reports = {}
        self.fd = fd
        self.agent_fd_table = {}
        self.matchingTable = {}
        

    def setInitConnetion(self,agent_fd, _):
        fd_num = agent_fd.fileno()
        agent_ip = agent_fd.getpeername()[0]

        sEPOLL.register(fd_num, select.EPOLLIN) 
        self.agent_fd_table[fd_num] = self.matchingTable[agent_ip] = agent_fd

        requests.post(WEB_URL+'/agent/add' , json = {'ip':agent_ip} )# notify to web


    def hasAllPackets(self,idx):
        try:
            packet_cnt = len(self.temp_reports[idx])
        except KeyError:
            return False
        
        if packet_cnt == 2:
            t = {'attck_id':idx}
            self.temp_reports[idx].update(t)
            return True
        return False

    def pop_item(msg):
        msg.pop('type') # remove 'type' key
        who = msg.pop('who') # sender or recevier
        attack_id = msg.pop('attack_id')
        return who, attack_id

    def removeAgent(self,fileno, agent_ip ):
        sEPOLL.unregister(fileno)
        self.agent_fd_table.pop(fileno).close()
        send_data = {'ip':agent_ip}
        requests.post(WEB_URL+'/agent/del',json = send_data) 

    def processingReceivedMsg(self, fileno, msg):

        if msg['type'] == "web": # command received from web
            for contents in msg['command']: 
                self.matchingTable[contents['src_ip']].send(contents)

        elif msg['type'] == "report": #commnad received from agent
            who, attack_id = self.pop_item(msg)
            
            if who == "target": 
                #report of target attack
                send_data = {'attack_id':attack_id,'pkts':msg['pkts']}
                requests.post(WEB_URL+'/report/target', json = send_data)

            else: 
                # agent <-> agent ATTACK
                self.temp_reports[attack_id][who] = msg['pkts']
                if self.hasAllPackets(attack_id):
                    requests.post(WEB_URL+'/report/pkt', json = self.temp_reports[attack_id])
                    self.temp_reports[attack_id].pop()

        elif msg['type'] == "scan": # sedn to webserver
            url = WEB_URL +'/report/scan' 
            msg.pop('type')
            requests.post(url, json = msg)
        
        elif msg['type'] == "agent_list": #웹서버가 에이전트 리스트를 요청할때
            url = WEB_URL +'/agent/list'
            requests.post(url, json = self.matchingTable)



    def run(self):
        try:
            while True:

                events = sEPOLL.poll(1)
                for fileno, event in events:

                    if fileno == self.fd.fileno(): # new user add
                        logging.info("[*]   Connectioned Agent!")
                        self.setInitConnetion(self.fd.accept())

                    elif event & select.EPOLLIN: # Recevie Client commands
                        logging.info("[*]   Recevied Data From Agent!")

                        buf = self.agent_fd_table[fileno].recv(4096)

                        if not buf: #remove agent
                            agent_ip = self.agent_fd_table[fileno].getpeername()[0]
                            self.removeAgent(fileno, agent_ip)
                            break

                        msg = bson.loads(buf)
                        self.processingReceivedMsg(fileno, msg)

                        
                    elif event & select.EPOLLOUT:
                        sEPOLL.modify(fileno, select.EPOLLIN)
                    
                
        finally:
            sEPOLL.unregister(self.fd.fileno())
            sEPOLL.close()
            self.fd.close()


if __name__ == "__main__":
    fd_server = setupSocket()
    sEPOLL.register(fd_server.fileno(), select.EPOLLIN)
   
    tcpServer = TCP_Server(fd_server)
    tcpServer.run()


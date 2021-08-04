import socket, select
import os
import bson
import logging
import requests
from multiprocessing import Process, Manager
from collections import defaultdict
import base64
### GLOBAL VARIABLE ###
HOST_IP = '0.0.0.0'
AGENT_PORT = 9000
WEB_PORT = 8000
WEB_URL = 'http://192.168.0.144:5000'

sEPOLL = select.epoll() # POLL for agent


def setupSocket():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST_IP, AGENT_PORT))
    server_socket.listen(1)

    return server_socket

class TCP_Server:
    def __init__(self,fd):
        self.temp_reports = defaultdict(dict)
        self.fd = fd
        self.agent_fd_table = {}
        self.matchingTable = {}
        

    def setInitConnetion(self,agent_fd):
        fd_num = agent_fd.fileno()
        agent_ip = agent_fd.getpeername()[0]

        sEPOLL.register(fd_num, select.EPOLLIN) 
        self.agent_fd_table[fd_num] = self.matchingTable[agent_ip] = agent_fd
        print("!", WEB_URL + "/agent/add")
        try:
            requests.post(WEB_URL+'/agent/add' , json = {'ip':agent_ip} )# notify to web
        except Exception as e:
            print(e)
            



    def hasAllPackets(self, idx):
        try:
            packet_cnt = len(self.temp_reports[idx])
        except KeyError:
            return False
        
        if packet_cnt == 5:
            self.temp_reports[idx]['attack_id'] = idx
            return True

        return False

    def pop_item(self, msg):
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
                print(contents, type(contents))
                self.matchingTable[contents['src_ip']].send(bson.dumps(contents))

        elif msg['type'] == "report": #commnad received from agent
            send_port = 0
            who, attack_id = self.pop_item(msg)
            REPORT = self.temp_reports[attack_id]
            
            if who == "send":
                send_port = msg.pop('port')
                REPORT['port'] = send_port
                REPORT['send_ip'] = self.agent_fd_table[fileno].getpeername()[0]

            elif who == "recv":
                REPORT['recv_ip'] = self.agent_fd_table[fileno].getpeername()[0]

            if who == "target": 
                #report of target attack
                send_data = {'attack_id':attack_id,'pkts':msg['pkts']}
                requests.post(WEB_URL+'/report/target', json = send_data)

            else: 
                # agent <-> agent ATTACK
                REPORT[who] = list(map(base64.b64encode, msg['pkts']))
                # self.temp_reports[]               
                if self.hasAllPackets(attack_id):
                    print("REPORT: ", REPORT)
                    REPORT["attack_id"] = attack_id
                    requests.post(WEB_URL+'/report/pkt', json = self.temp_reports[attack_id])
                    msg = {
                        "type": "unlock",
                        "port": REPORT['port'],
                    }
                    print("UNLOCK", msg)
                    self.matchingTable[REPORT['recv_ip']].send(bson.dumps(msg))
                    self.matchingTable[REPORT['send_ip']].send(bson.dumps(msg))
                    self.temp_reports.pop(attack_id)

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
                print("[*]  Wait")
                #events = sEPOLL.poll(1)
                events = sEPOLL.poll()
                for fileno, event in events:

                    if fileno == self.fd.fileno(): # new user add
                        logging.info("[*]   Connectioned Agent!")
                        conn_sock,_ = self.fd.accept()
                        self.setInitConnetion(conn_sock)

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

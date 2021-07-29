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

agent_fd_table={}
matchingTable={}


sEPOLL = select.epoll() # POLL for agent


def  setupSocket():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(HOST_IP, AGENT_PORT)
    
    #backlog는 연결이 대기할 수 있는 큐의 갯수이다. 
    # 만약 backlog에 연결이 모두 찬 상태에서 새로운 연결을 시도한다면, 
    # 클라이언트는 ECONNREFUSED 에러를 받게될 것이
    server_socket.listen(1)

    return server_socket



def convertByte2Dict(msg):
    return bson.loads(msg.decode('utf-8').reploace("'",'"'))


class TCP_Server:
    def __init__(self,fd, _):
        self.temp_reports = {}
        self.fd = fd
        

    def isAttackCommand(self, msg):
        return msg

    def isResultOfAttackOrScan(self,msg):
        return "report" or "scan" in msg['type']
    
        
       
    
    #def isAgentInfo(self, msg):
    #    return msg['uuid'] and msg['ip']

    def isScanCommand(self, msg):
        return "scan" in msg['type']

    def setInitConnetion(self,agent_fd, _):
        
        fd_num = agent_fd.fileno()
        agent_ip = agent_fd.getpeername()[0]
        sEPOLL.register(fd_num, select.EPOLLIN) # when EPOLLOUT?
        
        agent_fd_table[fd_num] = agent_fd
        
        matchingTable[agent_ip] = agent_fd  #matching table setting {agent_fd: {} ip:1231231}}
        
        sned_data = {'ip':agent_ip}
        requests.post(WEB_URL+'/agent/add' , json = sned_data)# notify to web

    def getAgentUUID(self,fd):
        return matchingTable[fd]['uuid']

    def getAgentFD(self,ip): #{fd:}
        for total in matchingTable.items():
            for fd , _ in total:
                if ip == matchingTable[fd]['ip']:
                    return fd
        return None
    def hasAllPackets(self,idx):
        try:
            packet_cnt = len(self.temp_reports[idx])
        except:
            return False
        
        if packet_cnt == 2:
            t = {'attck_id':idx}
            self.temp_reports[idx].update(t)
            return True


    def popItem(msg):
        msg.pop('type') #remove 'type' key
        who = msg.pop('who') #sender or recevier
        attack_id = msg.pop('attack_id')
        return who, attack_id


    def processingReceivedMsg(self, msg, fileno):

        if msg['type'] == "web": # command received from web

            for contents in msg['command']: 
                matchingTable[contents['src_ip']].send(contents)

        elif msg['type'] == "report": #commnad received from agent
            
            who, attack_id = self.popItem(msg)
            
            if who == "target":
                send_data = {'attack_id':attack_id,'pkts':msg['pkts']}
                requests.post(WEB_URL+'/report/target', json = send_data)
            else:
                self.temp_reports[attack_id].update({who :msg['pkts']})

                if self.hasAllPackets(attack_id):
                    requests.post(WEB_URL+'/report/pkt',json = self.temp_reports)
                
            

        elif msg['type'] == "scan": # sedn to webserver
            url = WEB_URL +'/report/scan' 
            msg.pop('type')
            requests.post(url,json = msg)

        

    def run(self):
        try:
            while True:

                events = sEPOLL.poll(1)
                for fileno, event in events:

                    if fileno == self.fd.fileno(): #new user add
                        logging.info("[*]   Connectioned Agent!")
                        self.setInitConnetion(self.fd.accept())

                    elif event & select.EPOLLIN: # Recevie Client commands
                        logging.info("[*]   Recevied Data From Agent!")
                        
                        msg = bson.loads(agent_fd_table[fileno].recv(4096)) # Get message from cilent # carriage return remove
                        
                        self.processingReceivedMsg(msg,fileno)

                        
                    elif event & select.EPOLLOUT:
                        #
                        #
                        #
                        sEPOLL.modify(fileno, select.EPOLLIN)

                    elif event & select.EPOLLHUP: # connetion close
                        agent_ip = agent_fd_table[fileno].getpeername()[0]
                        sEPOLL.unregister(fileno)
                        agent_fd_table[fileno].close()
                        del agent_fd_table[fileno]

                        
                        send_data = {'ip':agent_ip}
                        requests.post(WEB_URL+'/agent/del',json = send_data) ###
                
        finally:
            sEPOLL.unregister(self.fd.fileno())
            sEPOLL.close()
            self.fd.close()


if __name__ == "__main__":
    fd_server , fd_web = setupSocket()
    sEPOLL.register(fd_server.fileno(), select.EPOLLIN)
   
    ##웹 서버랑 epoll을 구지 하지 않아도 된다. 다중에이전트랑 통신하기 위해 epoll을 사용하는데 
    #웹이랑 1:1이니 echo socket구현해서 해도 되지 않나?
    tcpServer = TCP_Server(fd_server)
    
    pid = os.fork()
    if pid == 0: #child process
        print("123123") 
        #웹서버랑 통신하기위해 소켓이 필요하다면 
        #1. 자식프로세스 생성
        #2. 자식이 포트를 열게한다.
        #3. shared memory를 사용해해서 자원을 공유한다.
    else:
        tcpServer.run()


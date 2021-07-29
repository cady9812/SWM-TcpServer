import socket, select
import os
import json
import logging
import requests
from multiprocessing import Process, Manager


### GLOBAL VARIABLE ###
HOST_IP = '0.0.0.0'
AGENT_PORT = 9000
WEB_PORT = 8000
WEB_URL = 'http://localhost:5000'

agent_fd_table={}
agent_buffer={}

matchingTable={}


sEPOLL = select.epoll() # POLL for agent

manager = Manager()
d = manager.dict()



'''
AgentInfo ={'uuid' : 123-1-2312312-,
            'ip' : 128.0.0.1,
            }
'''

'''
matchingTable ={ 'fd' : {'uuid' : 123123123, 
                        'agent_ip' : 127.0.0.1,
                        },
                 'fd2' : ('uuid' :4566643123,
                         'agent_ip': 120.0.0.1),
                }
'''


def  setupSocket():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(HOST_IP, AGENT_PORT)
    
    #backlog는 연결이 대기할 수 있는 큐의 갯수이다. 
    # 만약 backlog에 연결이 모두 찬 상태에서 새로운 연결을 시도한다면, 
    # 클라이언트는 ECONNREFUSED 에러를 받게될 것이
    server_socket.listen(1)


    web_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    web_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    web_server_socket.bind(HOST_IP, WEB_PORT)
    web_server_socket.listen(1)


    return server_socket , web_server_socket



def convertByte2Dict(msg):
    return json.loads(msg.decode('utf-8').reploace("'",'"'))


class TCP_Server:
    def __init__(self,fd, _):
        self.fd = fd


    def isAttackCommand(self, msg):
        return "attack_target" or "attack_secu" in msg

    def isResultOfAttackOrScan(self,msg):
        return msg['pkts'] or msg['service_product'] # msg[kts] erro 
       
    
    def isAgentInfo(self, msg):
        return msg['uuid'] and msg['ip']

    def isScanCommand(self, msg):
        return msg['type'] == "scan"

    def setInitConnetion(self,agent_fd, _):
        
        #agent_fd.setblocking(0)
        sEPOLL.register(agent_fd.fileno(), select.EPOLLIN) # when EPOLLOUT?

        agent_fd_table[agent_fd.fileno()] = agent_fd
        agent_buffer[agent_fd.fileno()] ={} #request init
        matchingTable[agent_fd.fileno()] = {} #matching table setting {agent_fd: {uuid : 123123, ip:1231231}}
        
    def getAgentUUID(self,fd):
        return matchingTable[fd]['uuid']

    def getAgentFD(self,ip):
        for total in matchingTable.items():
            for fd , _ in total:
                if ip == matchingTable[fd]['agent_ip']:
                    return fd
        return None


    def processingReceivedMsg(self, msg, fileno):

        if self.isAgentInfo(msg): ### Recv userInfo ( uuid, ip ) like {'uuid':123123,'ip':'128..0.1'}
            matchingTable[fileno] = msg   
            requests.post(WEB_URL+'/agent/info',msg) 


        if self.isScanCommand(msg):
            srcAgent_fd = self.getAgentFD(msg['src_ip'])
            agent_fd_table[srcAgent_fd].send(msg)


        if self.isAttackCommand(msg): 
            fd_srcAgent = self.getAgentFD(msg['src_ip'])
            fd_dstAgent = self.getAgentFD(msg['dst_ip'])
            agent_fd_table[fd_srcAgent].send(msg)
            
            if msg['type'] == "attack_secu": # If agent vs agent , send defendse
                #에이전트끼리 서로 공격하는 거면, send를 2번 해줘야하는데,,
                #애초에 dict으로 attack,defense key를 주는것이,,
                agent_fd_table[fd_dstAgent].send()

        if self.isResultOfAttackOrScan(msg): # Send attack or scan result
            logging.info    ("[*]   Send 'Report or Scan Result' to webserver")
            
            if msg['pkts']: # if this message included packet, it is report 
                url = WEB_URL+'/report/'+self.getAgentUUID(fileno) # /report/agent_uuid
            else:
                url = WEB_URL+'/scan-result'
            
            requests.post(url,data=msg)



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
                        
                        msg = agent_fd_table[fileno].recv(1024) # Get message from cilent # carriage return remove
                        msg = convertByte2Dict(msg)
                        
                        self.processingReceivedMsg(msg,fileno)

                        
                    elif event & select.EPOLLOUT:
                        #
                        #
                        #
                        sEPOLL.modify(fileno, select.EPOLLIN)

                    elif event & select.EPOLLHUP: # connetion close
                        sEPOLL.unregister(fileno)
                        agent_fd_table[fileno].close()
                        del agent_fd_table[fileno] 
                
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


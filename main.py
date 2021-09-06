#!/usr/bin/env python3
import socket, select
import os
import bson, json
import logging
import requests
from multiprocessing import Process, Manager
from collections import defaultdict
import base64
### GLOBAL VARIABLE ###
import config, log_config
BUF_SIZE = 0x1000
WEB_URL = config.WEB_URL
AGENT_PORT = config.AGENT_PORT
MY_IP = config.MY_IP
DEBUG = True

# For colored logging
END = "\033[0m"
YELLOW = "\033[33m"
MAGENT = "\033[35m"
GREEN = "\033[32m"
BLUE = "\033[34m"
CYAN = "\033[36m"
RED = "\033[31m"

logger = log_config.get_custom_logger(__name__)
sEPOLL = select.epoll() # POLL for agent


def setupSocket():
    logger.info("Setting up socket...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((MY_IP, AGENT_PORT))
    server_socket.listen(1)

    return server_socket


def http_request(url, method, debug=DEBUG, json=None):
    if debug:
        print(f"[http_Request] Debugging Mode")
        return

    print(f"[http_Request] {url} | {method} | {json}")
    try:
        if method == "GET":
            requests.get(url)
        elif method == "POST":
            requests.post(url, json=json)
    except:
        logger.error(f"http_Request fail")
        

class TCP_Server:
    def __init__(self,fd):
        self.temp_reports = defaultdict(dict)
        self.fd = fd
        self.agent_fd_table = {}
        self.ip_to_sock = {}
        self.web_table = {}


    def setInitConnetion(self, agent_sock):
        fd_num = agent_sock.fileno()
        agent_ip = agent_sock.getpeername()[0]
        logger.debug(f"fd: {fd_num} / ip: {agent_ip}")
        
        # epoll 이벤트로 등록하기 전에, 일단 introduce 처리
        msg = bson.loads(agent_sock.recv(BUF_SIZE))
        logger.info(f"[introduce] {msg}")

        if not msg['type'] == 'introduce':
            logger.error(f"Protocol Error - new connection should start with self-introduce")
            return None
        
        sEPOLL.register(fd_num, select.EPOLLIN)

        client_type = msg['detail']

        if client_type == "web":
            self.web_table[fd_num] = agent_sock
            logger.debug(f"{BLUE}WEB TABLE ==> {self.web_table}{END}")

        elif client_type == "agent":
            self.agent_fd_table[fd_num] = self.ip_to_sock[agent_ip] = agent_sock
            http_request(WEB_URL+'/agent/add', "POST", json = {'ip':agent_ip, 'id': fd_num})
            
            logger.debug(f"{BLUE}AGENT ==> {self.agent_fd_table} {self.ip_to_sock}{END}")


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


    def removeAgent(self, fileno):
        if fileno in self.agent_fd_table:
            agent_ip = self.agent_fd_table[fileno].getpeername()[0]
        elif fileno in self.web_table:
            agent_ip = self.web_table[fileno].getpeername()[0]

        logger.debug(f"Trying to remove agent {fileno} {agent_ip}")
        sEPOLL.unregister(fileno)

        # web 의 fd라면 그냥 끝
        if fileno in self.web_table:
            self.web_table.pop(fileno)
        
        else:
            self.agent_fd_table.pop(fileno).close()
            self.ip_to_sock.pop(agent_ip).close()
            data = {'ip':agent_ip}
            http_request(WEB_URL+'/agent/del', "POST", json=data)

        return


    def processingReceivedMsg(self, fileno, msg):
        logger.debug(f"Processing {msg}")
        if msg['type'] == "web": # command received from web
            logger.debug(f"type web")
            for contents in msg['command']:
                contents['ticket'] = fileno     # scan 결과로 보내줄 fd
                logger.info(f"IP->SOCK mapping: {self.ip_to_sock}")
                self.ip_to_sock[contents['src_ip']].send(bson.dumps(contents))

        elif msg['type'] == "report": #commnad received from agent
            logger.debug(f"type report")
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
                http_request(WEB_URL+'/report/target', "POST", json=send_data)

            else:
                # agent <-> agent ATTACK
                REPORT[who] = list(map(base64.b64encode, msg['pkts']))
                # self.temp_reports[]            
                if self.hasAllPackets(attack_id):
                    print("REPORT: ", REPORT)
                    REPORT["attack_id"] = attack_id
                    http_request(WEB_URL+'/report/pkt', "POST", json=self.temp_reports[attack_id])
                    msg = {
                        "type": "unlock",
                        "port": REPORT['port'],
                    }
                    logger.warning(f"UNLOCK - {msg}")
                    self.ip_to_sock[REPORT['recv_ip']].send(bson.dumps(msg))
                    self.ip_to_sock[REPORT['send_ip']].send(bson.dumps(msg))
                    self.temp_reports.pop(attack_id)

        elif msg['type'] == "scan": # send to webserver
            logger.debug(f"type scan")
            url = WEB_URL +'/report/scan'
            msg.pop('type')

            ticket = msg['ticket']
            sckt = self.web_table[ticket]
            logger.warning(f"[scan][result] send {msg} to {sckt}")
            sckt.send(bson.dumps(msg))
        
        elif msg['type'] == "agent_list": #웹서버가 에이전트 리스트를 요청할때
            logger.debug(f"type agent_list")
            url = WEB_URL +'/agent/list'
            http_request(url, "POST", json=self.ip_to_sock)

        elif msg['type'] == 'malware':
            logger.debug(f"type malware")
            url = WEB_URL + "/report/malware"
            http_request(url, "POST", json=msg)

        else:
            logger.warning(f"{RED}Not implemented{END}")

    def run(self):
        try:
            while True:
                logger.debug(f"{YELLOW}Waiting for new connection...{END}")
                events = sEPOLL.poll()
                for fileno, event in events:

                    if fileno == self.fd.fileno(): # new user add
                        logger.info(f"{MAGENT}Connectioned Agent!{END}")
                        conn_sock,_ = self.fd.accept()
                        self.setInitConnetion(conn_sock)

                    elif event & select.EPOLLIN: # Receive Client commands
                        logger.debug("EVENT TRIGGERED")
                        if fileno in self.agent_fd_table:
                            sock = self.agent_fd_table[fileno]
                        elif fileno in self.web_table:
                            sock = self.web_table[fileno]
                        else:
                            logger.fatal("DEADBEEF")
                            exit(1)

                        buf = sock.recv(4096)
                        if not buf: #remove agent
                            logger.info(f"{RED}Delete Agent: {fileno}{END}")
                            self.removeAgent(fileno)
                            break

                        msg = bson.loads(buf)
                        logger.info(f"Recevied Data From {fileno}: {msg}")
                        self.processingReceivedMsg(fileno, msg)


                    elif event & select.EPOLLOUT:
                        logger.debug("???????????")
                        sEPOLL.modify(fileno, select.EPOLLIN)

        finally:
            logger.debug(f"{MAGENT}Bye Bye~{END}")
            sEPOLL.unregister(self.fd.fileno())
            sEPOLL.close()
            self.fd.close()


if __name__ == "__main__":
    fd_server = setupSocket()
    sEPOLL.register(fd_server.fileno(), select.EPOLLIN)
   
    tcpServer = TCP_Server(fd_server)
    tcpServer.run()

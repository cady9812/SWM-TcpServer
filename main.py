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
from config import *
import log_config
import utility

from pools import agent, web, report

BUF_SIZE = 0x1000

logger = log_config.get_custom_logger(__name__)
sEPOLL = select.epoll() # POLL for agent


class RelayServer(object):
    def __init__(self, sock):
        self.temp_reports = defaultdict(dict)
        self.listening_sock = sock

        self.agents = agent.AgentPool()
        self.webs = web.WebPool()
        self.reports = report.ReportPool()
        self.tmps = {}


    def set_init_connection(self, sock: socket.socket):
        # epoll 이벤트로 등록하기 전에, 일단 introduce 처리
        fd_num = sock.fileno()
        msg = bson.loads(sock.recv(BUF_SIZE))
        logger.debug(f"[introduce] {msg}")

        if not msg['type'] == 'introduce':
            logger.error(f"Protocol Error - new connection should start with self-introduce")
            exit(1)

        sEPOLL.register(fd_num, select.EPOLLIN)

        client_type = msg['detail']
        if client_type == "web":
            self.webs.add(sock)

        elif client_type == "agent":
            self.agents.add(sock)
            # for debug
            # sock.send(bson.dumps({"type" : "endpoint","attack_id" : 13,
            # "download": "http://172.30.1.39:8000/12.exe","filename": "12.exe","ticket": 3}))
        
        elif client_type == "tmp":
            self.tmps[fd_num] = sock
            logger.debug(f"{BLUE}[TMP] - {sock}{END}")

        return


    def delete_fd(self, fd):
        logger.debug(f"{RED}Delete {fd}{END}")
        if self.agents.has(fd):
            self.agents.delete(fd)
        
        elif self.webs.has(fd):
            self.webs.delete(fd)
        
        elif fd in self.tmps:
            self.tmps.pop(fd)

        else:
            logger.error(f"{RED}No such {fd}{END}")
            exit(1)

        sEPOLL.unregister(fd)
        self.reports.delete_all(fd) # 만약 해당 fd 의 report 가 혹시라도 남아있다면 모두 삭제


    def process_commands(self, fd, msg):
        logger.debug(f"{GREEN}Processing - {fd}{END} / {msg}")
        cmd_type = msg.pop('type')

        # 웹에서 날라온 명령
        if cmd_type == "web": # command received from web
            logger.debug(f"type web")
            for contents in msg['command']:
                contents['ticket'] = fd     # scan 결과로 보내줄 fd
                ip = contents['src_ip']
                self.agents.send_to(ip, contents)

        # 보안 장비 정검
        elif cmd_type == "report": #commnad received from agent
            logger.debug(f"type report")
            who = msg['who']
            attack_id = msg['attack_id']
            ticket = msg['ticket']

            REPORT = self.reports.report(msg)
            if who == "send":
                send_port = msg['port']
                REPORT['port'] = send_port
                REPORT['send_ip'] = utility.get_ip_from_sock(self.tmps[fd])

            elif who == "recv":
                REPORT['recv_ip'] = utility.get_ip_from_sock(self.tmps[fd])

            # agent <-> agent ATTACK
            REPORT['type'] = 'pkt'
            REPORT[who] = list(map(base64.b64encode, msg['pkts']))
            if "send_ip" in REPORT and "recv_ip" in REPORT:
                sock = self.webs.get(ticket)
                utility.send_report(sock, REPORT)

                msg = {
                    "type": "unlock",
                    "port": REPORT['port'],
                }
                logger.warning(f"UNLOCK - {msg}")
                self.agents.sock_of(REPORT['recv_ip']).send(bson.dumps(msg))
                self.agents.sock_of(REPORT['send_ip']).send(bson.dumps(msg))
                self.reports.delete(ticket, attack_id)

        # nmap 스캔 결과
        elif cmd_type == "scan": # send to webserver
            msg['type'] = "scan"
            logger.debug(f"type scan")
            ticket = msg['ticket']
            sock = self.webs.get(ticket)
            logger.info(f"[scan_result] send {msg} to {sock}")
            utility.send_report(sock, msg)

        # agent_list : 사실 안쓰임 (?)
        elif cmd_type == "agent_list": #웹서버가 에이전트 리스트를 요청할때
            logger.debug(f"type agent_list")
            utility.http_request('/agent/list', "POST", json=self.ip_to_sock)

        # 악성코드 분석 결과
        elif cmd_type == 'malware':
            msg['type'] = "malware"
            logger.debug(f"type malware")
            ticket = msg['ticket']
            sock = self.webs.get(ticket)
            utility.send_report(sock, msg)

        # target 공격에서 아직 리포트 기능을 agent 에 넣지 않았음...
        # TODO
        elif cmd_type == "target":
            msg['type'] = 'target'
            ticket = msg['ticket']
            sock = self.webs.get(ticket)
            utility.send_report(sock, msg)
        
        elif cmd_type == "endpoint":
            ticket = msg['ticket']
            sock = self.webs.get(ticket)
            utility.send_report(sock, msg)

        else:
            logger.warning(f"{RED}Not implemented{END}")

    # main loop body
    def body(self):
        logger.debug(f"{YELLOW}Waiting for new connection...{END}")
        events = sEPOLL.poll()
        for fileno, event in events:
            logger.debug(f"{YELLOW}[!]{END} Event triggered")
            if fileno == self.listening_sock.fileno(): # new user add
                conn_sock, _ = self.listening_sock.accept()
                self.set_init_connection(conn_sock)

            elif event & select.EPOLLIN: # get message
                if self.agents.has(fileno):
                    sock = self.agents.get(fileno)
                elif self.webs.has(fileno):
                    sock = self.webs.get(fileno)
                elif fileno in self.tmps:
                    sock = self.tmps[fileno]
                else:
                    logger.fatal("DEADBEEF")
                    exit(1)

                buf = utility.recv_data(sock)
                # buf = sock.recv(10240)
                if buf:
                    msg = bson.loads(buf)
                    logger.info(f"Recevied Data From {fileno}: {msg}")
                    self.process_commands(fileno, msg)
                else:
                    # Close connection
                    self.delete_fd(fileno)

            elif event & select.EPOLLOUT:
                logger.debug("What Happened?")


    def run(self):
        try:
            while True:
                self.body()
        except KeyboardInterrupt:
            pass
        finally:
            logger.debug(f"{RED}Terminating Server...{END}")
            sEPOLL.unregister(self.listening_sock.fileno())
            sEPOLL.close()
            self.listening_sock.close()


if __name__ == "__main__":
    listening_sock = utility.setup_socket()
    sEPOLL.register(listening_sock.fileno(), select.EPOLLIN)

    server = RelayServer(listening_sock)
    logger.info(f"{CYAN}Lets go!{END}")
    server.run()

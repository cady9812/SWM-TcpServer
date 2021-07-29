import select
import socket
import sys
import bson
import requests

def request_json(url, data):
    try:
        requests.post(url, json = data)
    except:
        print(f"{url} off - {data}")

class TcpServer(object):
    IP = "0.0.0.0"
    PORT = -1
    MAX_CLI = 100   # 최대 100개의 client 와 연결 가능
    BUF_SIZE = 0x1000
    connections = {}

    id_to_socket = {}
    last_agent_id = 0

    WEB_URL = "http://localhost:5000/"
    ADD_AGENT = WEB_URL + "newAgent"
    DELETE_AGENT = WEB_URL + "deleteAgent"
    REPORT = WEB_URL + "report"

    num_waiting_reports = 0
    reported_data = {}

    def __init__(self, port = 9000):
        self.PORT = port
        self._prepare_listening_sock()
        self._prepare_epoll()
        return

    def _prepare_listening_sock(self):
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind((self.IP, self.PORT))
        listen_sock.listen(5)
        
        self.listen_sock = listen_sock
        return

    def _prepare_epoll(self):
        e = select.epoll(self.MAX_CLI)
        e.register(self.listen_sock.fileno(), select.EPOLLIN)
        
        self.epoll = e
        return

    def _process_event(self, ev):
        fd, event = ev
        epoll = self.epoll
        C = self.connections
        listen_sock = self.listen_sock

        if fd == listen_sock.fileno():
            conn_sock, cli_info = listen_sock.accept()
            # cli_info 에서 ip:port 가 localhost:5000 이면 web socket 이라고 판단해도 될듯
            # 지금은 그냥 json data 에 의존
            epoll.register(conn_sock.fileno(), select.EPOLLIN)
            C[conn_sock.fileno()] = conn_sock

            return None

        else:
            if event & select.EPOLLIN:
                buf = C[fd].recv(self.BUF_SIZE)

                if not buf:
                    epoll.unregister(fd)
                    s = C.pop(fd)
                    s.close()
                    for id, sock in self.id_to_socket.items():
                        if sock != s:
                            continue
                        request_json(self.DELETE_AGENT, {"id": id})
                        break

                    print("closed", fd)
                    return None

                return buf

            return None

    def _process_command(self, fd, msg):
        cmd = {}
        C = self.connections
        id2sock = self.id_to_socket

        try:
            cmd = bson.loads(msg)
            cmd["type"]
            print(cmd)

        except Exception as e:
            print("Wrong json format", cmd)
            return
            # nmap 을 localhost 에 날리면 이상한 값이 9000포트로 들어올 수 있기 때문에...

        # 새로운 agent 가 추가됨.
        if cmd['type'] == "agent":
            self.last_agent_id += 1

            ip = cmd['ip']  # 자기 ip 를 보낼 필요도 없긴함.. socket 에 들어있는 정보라서
            id = self.last_agent_id

            print("New Agent", ip, id)
            id2sock[id] = C[fd]

            # 새로 추가된 agent 를 서버에게 알림
            msg = {
                "id": id,
                "ip": ip,
            }

            request_json(self.ADD_AGENT, msg)

            return

        # 웹 서버에게 agent 에게 수행할 업무를 알려줌
        elif cmd['type'] == "web":
            cmds = cmd['cmds']

            # 아마도 2개의 명령
            for command in cmds:
                # id 로 agent 를 특정할지, ip 로 특정할지 모르겠다.. id 가 쓸모가 있나?
                # -> 로컬에서 테스트하면 ip 가 같을 순 있긴함
                agent_id = command.pop("id")    # agent 가 자신의 id 를 알 필요가 없기 때문에

                if type(agent_id) is str:
                    agent_id = int(agent_id)

                if agent_id not in id2sock:
                    raise Exception("Wrong Agent Id")

                target_sock = id2sock[agent_id]

                print(f"send {command} to {target_sock}")

                # 현재는 한 시점에 오직 하나의 공격만 수행된다는 가정 하여 reports 변수를 하나만 두었음
                # 만약 추후에 여러 공격을 동시에 수행하도록 바꾼다면,
                # attack id 기반의 dictionary 로 num report 를 유지하면 될 듯
                try:
                    if command["type"] in ["attack_secu", "defense"]:
                        self.num_waiting_reports += 1

                except Exception as e:
                    raise Exception(f"cmd should has type: {command}")

                target_sock.send(bson.dumps(command))

            return

        # 여러 agent 로부터 온 report 를 보고 최종 결과를 내야 함.
        # attack_secu, defense 는 꼭 report 를 받아야함..
        # attack_secu 용
        elif cmd['type'] == "report":
            self.num_waiting_reports -= 1
            self.reported_data[cmd["type2"]] = cmd

            if self.num_waiting_reports == 0:
                attack_result = self.reported_data["attack"]
                defense_result = self.reported_data["defense"]
                result = {
                    "diff": list(set(attack_result["pkts"]) - set(defense_result["pkts"])),
                }

                request_json(self.REPORT, result)
                self.reported_data = {} # initialize
            return

        elif cmd["type"] == "malware":
            agent_id = cmd.pop("id")
            print(agent_id)
            pass

        elif cmd["type"] == "scan":
            scan_result = cmd["result"]
            return

        else:
            raise Exception("Not Implemented Type")

    def _process_events(self, events):
        for fd, ev in events:
            result = self._process_event((fd, ev))
            if not result:
                continue

            self._process_command(fd, result)

    def poll_once(self):
        listen_sock = self.listen_sock
        events = self.epoll.poll()
        self._process_events(events)
        
        return

    def run_server(self):
        while True:
            self.poll_once()

if __name__ == '__main__':
    port = 9000
    if len(sys.argv) == 2:
        port = int(sys.argv[1])

    t = TcpServer(port)
    t.run_server()

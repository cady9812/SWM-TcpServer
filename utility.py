import requests
from config import *
import log_config
import socket
import bson

logger = log_config.get_custom_logger(__name__)

def http_request(api, method, debug=DEBUG, json=None):
    request_url = WEB_URL + api
    if debug:
        logger.info(f"[http_Request] Debugging Mode")
        return

    logger.debug(f"[http_Request] {request_url} | {method} | {json}")
    try:
        if method == "GET":
            requests.get(request_url)
        elif method == "POST":
            requests.post(request_url, json=json)
    except:
        logger.error(f"http_Request fail")


def get_ip_from_sock(sock: socket.socket):
    return sock.getpeername()[0]


def setup_socket():
    logger.info(f"{YELLOW}Setting up socket... {MY_IP}:{AGENT_PORT}{END}")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((MY_IP, AGENT_PORT))
    server_socket.listen(1)

    return server_socket

def send_report(sock: socket.socket, report: dict):
    logger.info(f"{GREEN}Send {report} to {sock}{END}")
    data = bson.dumps(report)
    sock.send(data)
    sock.close()    # End Of Report


def recv_data(sckt):
    result = b''
    BUF_SIZE = 4096
    while True:
        tmp = sckt.recv(BUF_SIZE)
        if not tmp:
            break
        result += tmp
    
    print(len(result))
    return result

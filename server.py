#!/usr/bin/python3
import socket
import select
import sys, os

SERVED_DIR = 'web'
SERVED_DIR_PATH = '' # autofilled
RECV_SIZE = 2048
MAX_REQSIZE = 10000

STATUS_CODES_FILENAME = 'status_codes.csv'
status_codes = {b'876': b'You got me'}
STATUS_TEMPLATE_FILENAME = 'status_template.html'

def run(addr, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setblocking(0)
    server_socket.bind((addr, port))
    server_socket.listen()
    inputs = [ server_socket ]
    outputs = []
    received = dict()
    requests = dict()
    while inputs:
        to_read, to_write, err = select.select(inputs, outputs, inputs)
        if err:
            for i, error_socket in enumerate(err):
                print(f'[ERROR] {i}:', error_socket, file=sys.stderr)
        for s in to_read:
            if s == server_socket:
                client_socket, client_address = s.accept()
                print('[ACCEPT]', client_socket, f'ADDR {client_address}')
                client_socket.setblocking(0)
                inputs.append(client_socket)
                received[client_socket] = b''
            else:
                data = s.recv(RECV_SIZE)
                if not data:
                    # `s` disconnected
                    print('[DISCONNECTED]', s)
                    inputs.remove(s)
                    continue
                received[client_socket] += data
                print('[DATA', s.getpeername(), ']',received[client_socket])
                if len(received[client_socket]) > MAX_REQSIZE:
                    print('[REQUEST TOO LARGE]', s, file=sys.stderr)
                    inputs.remove(s)
                if received[client_socket].endswith(b'\r\n\r\n'):
                    requests[s] = parse_request(received[client_socket])
                    inputs.remove(s)
                    outputs.append(s)
                else:
                    print('[REQUEST DOESNT END WITH CRLFCRLF]')
        for s in to_write:
            print('[TO WRITE]', s)
            request = requests[s]
            if request['method'] != b'GET' or \
               request['version'] not in [b'HTTP/1.0', b'HTTP/1.1']:
                print('[BAD REQUEST]', request)
                s.sendall(compose_response_header(400))
                s.close()
                outputs.remove(s)
                continue
            found_resource = find_resource(request['resource'])
            print('[FOUND]', found_resource)
            if type(found_resource) == int: # 403, 403, 404
                s.sendall(compose_response_header(found_resource))
                s.sendall(html_status_response(found_resource))
                s.close()
                outputs.remove(s)
                continue
            try:
                with open(found_resource, 'rb') as f:
                    file = f.read()
                    file_len = len(file)
                    s.sendall(compose_response_header(200, length=file_len))
                    s.sendall(file)
                    s.close()
                    outputs.remove(s)
                    continue
            except PermissionError:
                s.sendall(compose_response_header(403))
                s.sendall(html_status_response(403))
                s.close()
                outputs.remove(s)

def parse_request(http):
    http_lines = http[:-4].split(b'\r\n')
    request = {}
    method, resource, version = http_lines[0].split(b' ', 3)
    request = {'method': method,
               'resource': resource,
               'version': version}
    for line in http_lines[1:]:
        key, value = line.split(b': ', 2)
        request[key] = value
    return request

def load_status_codes():
    with open(STATUS_CODES_FILENAME, 'rb') as f:
        for i, line in enumerate(f):
            if i == 0:
                continue
            code, reason = line.strip().split(b';')
            status_codes[int(code)] = reason

def compose_response_header(code, **kwargs):
    length = kwargs.get('length', None)
    header = b'HTTP/1.1 %d %b\r\n' % (code, status_codes[code])
    header += b'Server: uno chico, por?\r\n'
    if length:
        header += b'Content-Length: %d\r\n' % length
    header += b'\r\n'
    return header

def html_status_response(code):
    with open(STATUS_TEMPLATE_FILENAME, 'rb') as f:
        content = f.read()
        content = content.replace(b'[[HTTP_CODE]]', str(code).encode('utf-8'))
        content = content.replace(b'[[HTTP_REASON]]', status_codes[code])
        return content

def find_resource(name):
    if not name.startswith(b'/'):
        return 400
    resource_path = os.path.realpath(b'%b/%b' % (SERVED_DIR, name))
    print('[RESOURCE_PATH]', resource_path)
    if os.path.commonprefix([SERVED_DIR_PATH, resource_path]) != SERVED_DIR_PATH:
        return 403
    if os.path.isfile(resource_path):
        return resource_path
    return 404

def init():
    load_status_codes()
    global SERVED_DIR
    if type(SERVED_DIR) == str:
        SERVED_DIR = SERVED_DIR.encode('utf-8')
    global SERVED_DIR_PATH
    SERVED_DIR_PATH = os.path.realpath(SERVED_DIR)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} [ip] [port]')
        exit(1)
    addr, port = sys.argv[1:]
    init()
    try:
        run(addr, int(port))
    except KeyboardInterrupt:
        print('[BYE]')

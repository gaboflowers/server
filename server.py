#!/usr/bin/python3
import socket
import select
import sys, os

SERVED_DIR = 'web'    # <- SET THE FOLDER YOU WANT TO SERVE
SERVED_DIR_PATH = ''  # autofilled by init()
FILENAME_LOOKUP = [b'index.html', b'index.htm'] # names to look for if resource
                                                # is a folder
RECV_SIZE = 2048        # size of the block read from the socket
MAX_REQSIZE = 10000     # max size of an HTTP request

# HTTP codes
STATUS_CODES_FILENAME = 'status_codes.csv'
status_codes = {b'876': b'You got me'}
STATUS_TEMPLATE_FILENAME = 'status_template.html'

def run(addr, port):
    '''
    Runs an HTTP server at `addr`:`port`.

    - addr: str
    - port: int
    Returns:
      None
    '''
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setblocking(0)
    server_socket.bind((addr, port))
    server_socket.listen()
    inputs = [ server_socket ]
    outputs = []
    received = dict()  # data (bytes) received by socket
    requests = dict()  # parse_request dicts, by socket
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
                    del received[client_socket]
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
               request['version'] not in [b'', b'HTTP/1.0', b'HTTP/1.1']:
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
    '''
    Returns a dict with the keys 'method', 'resource' and 'version', parsing
    an HTTP header. If present, other headers will also be keys of the
    returned dict.

    Additional header keys and all of the values will be BYTES.
    The 'method', 'resource' and 'version' keys are STR, but their values are
    also BYTES.

    - http: bytes
    Returns:
      dict of [str|bytes] to [bytes]
    '''
    # Header lines are ALWAYS terminated by CRLF ("\r\n")
    http_lines = http[:-4].split(b'\r\n')
    request = {}
    # First line is HTTP Method, then Resource and optionally version
    # Ex: "GET /index.html"
    #     "GET /favicon.ico HTTP/1.1"
    method, resource_and_version = http_lines[0].split(b' ', 1)
    if b' ' in resource_and_version:
        resource, version = resource_and_version.split(b' ', 1)
    else:
        resource = resource_and_version
        version = b''
    request = {'method': method,
               'resource': resource,
               'version': version}
    # The following lines may be some other HTTP headers
    # Ex: "User-Agent: Mozilla/5.0"
    #     "Accept-Encoding: gzip, deflate, br"
    for line in http_lines[1:]:
        key, value = line.split(b': ', 1)
        request[key] = value
    return request

def load_status_codes():
    '''
    Read the status codes from the STATUS_CODES_FILENAME file,
    populating the `status_codes` global dict.
    '''
    with open(STATUS_CODES_FILENAME, 'rb') as f:
        for i, line in enumerate(f):
            if i == 0:
                continue
            code, reason = line.strip().split(b';')
            status_codes[int(code)] = reason

def compose_response_header(code, **kwargs):
    '''
    Returns the HTTP headers given the HTTP status `code`.
    If `length` is passed, the 'Content-Length' header is also added.

    - code: int
    Keyword arguments:
      length: int
    Returns:
      bytes
    '''

    length = kwargs.get('length', None)
    header = b'HTTP/1.1 %d %b\r\n' % (code, status_codes[code])
    header += b'Server: uno chico, por?\r\n'
    if length:
        header += b'Content-Length: %d\r\n' % length
    header += b'\r\n'
    return header

def html_status_response(code):
    '''
    Returns an HTML info webpage given the HTTP status `code` passed.
    The webpage is based on the STATUS_TEMPLATE_FILENAME template.

    - code: int
    Returns:
      bytes
    '''
    with open(STATUS_TEMPLATE_FILENAME, 'rb') as f:
        content = f.read()
        content = content.replace(b'[[HTTP_CODE]]', str(code).encode('utf-8'))
        content = content.replace(b'[[HTTP_REASON]]', status_codes[code])
        return content

def find_resource(name):
    '''
    Finds the resource `name` within the SERVED_DIR.
    If found, returns the full path filename as a string.
    If not found within SERVED_DIR, returns an integer HTTP error code.

    - name: string
    Returns:
      str or int
    '''
    if not name.startswith(b'/'):
        return 400
    resource_path = os.path.realpath(b'%b/%b' % (SERVED_DIR, name))
    print('[RESOURCE_PATH]', resource_path)
    if os.path.commonprefix([SERVED_DIR_PATH, resource_path]) != SERVED_DIR_PATH:
        return 403
    if os.path.isfile(resource_path):
        return resource_path
    if os.path.isdir(resource_path):
        for possible_filename in FILENAME_LOOKUP:
            possible_path =  os.path.join(resource_path, possible_filename)
            print('[RESOURCE_PATH IS DIR] Trying', possible_path)
            if os.path.isfile(possible_path):
                return possible_path
    return 404

def init():
    '''
    Loads initial global variables.
    '''
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

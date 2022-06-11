# smashthestack
A python tool which automates simple buffer overflow attacks for applications that require a tcp socket to interact with.

## Usage
~~~
usage: PyFuzzer -s/--server <DOMAIN> -p/--port <PORT>

Fuzzing for finding vulnerable BoF vulnerabilities

options:
  -h, --help            show this help message and exit
  --server SERVER, -s SERVER
                        The host you want to connect with
  --port PORT, -p PORT  The port you want to connect to
  --data DATA, -d DATA  The payload that needs to prepend the buffer
  --buffer BUFFER, -b BUFFER
                        The size of the buffer
  --memaddr MEMADDR, -m MEMADDR
                        Memory address for "JMP ESP"
  --nops NOPS, -n NOPS  number of NOPS to use for padding, default is 32
  --overflow OVERFLOW, -o OVERFLOW
                        The exploit code to jump into
~~~


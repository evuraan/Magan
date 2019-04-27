# Magan

Magan is a DNS over HTTPS (DoH) server. 

The [C](https://github.com/evuraan/Magan/blob/master/src/magan.c) version is recommended; also available are the [Go](https://github.com/evuraan/Magan/blob/master/src/magan_go.go)  and [Python3](https://github.com/evuraan/Magan/blob/master/src/magan.py) variants. 

A few pre-built binaries for Linux and Windows are available [here](https://github.com/evuraan/Magan/tree/master/bin).

## Build instructions

### The C version


We need `libcurl4-openssl-dev` and `libjson-c`, usually installed on Debian thusly:
<pre>
$ sudo apt install libjson-c libcurl4-openssl-dev
</pre>
Once all the pre-requisites are met, compile magan as:
<pre>
$ gcc  magan.c -pthread -lcurl -ljson-c -o magan-$(uname -m) 
</pre>
<i>(Also see [`make.sh`](https://github.com/evuraan/Magan/blob/master/scripts/make.sh).)</i>

### Building the Go variant
See [`make_go_binaries.sh`](https://github.com/evuraan/Magan/blob/master/scripts/make_go_binaries.sh) 

### The Python3 Version
We need latest [`scapy`](https://github.com/secdev/scapy):

<pre>
$ pip3 install scapy
</pre>
and then:
<pre>
$ ./magan.py -h
Usage:
  -h  --help         print this usage and exit
  -p  --port         alternate port to listen
  -v  --version      print version information and exit
</pre>



## Basic Usage

<pre>
$ ./magan --help
Usage: ./magan [options]
  -h  --help         print this usage and exit
  -p  --port         alternate port to listen
  -v  --version      print version information and exit
</pre>


### to listen on non-privileged port
You don't need root privileges if you are using port > 1024: 
<pre>
$ ./magan-armv7l -p 3131
Thu Apr  4 19:34:48 2019 Magan[26795]: Magan/1.2
Thu Apr  4 19:34:48 2019 Magan[26795]: Listening on port: 3131
Thu Apr  4 19:34:48 2019 Magan[26795]: Ready
..
</pre>


### to listen on privileged port

you'd need root privs if you want to listen in on port number less than 1024
<pre>
$ sudo ./magan-armv7l 
Thu Apr  4 19:35:20 2019 Magan[26823]: Magan/1.2
Thu Apr  4 19:35:20 2019 Magan[26823]: Listening on port: 53
Thu Apr  4 19:35:20 2019 Magan[26823]: Ready
..
</pre> 

## Startup

Startup can be as simple as adding a line to your /etc/crontab:
<pre>
*/5 * * * *    someuser     /usr/local/bin/magan -p 1039 1>/dev/null 2>/dev/null
</pre>
If you are running as root, then:
<pre>
*/5 * * * *    root     /usr/local/bin/magan -p 53 1>/dev/null 2>/dev/null
</pre>

## Notes
### i/o timeout
With the Go variant, you may encounter this chicken or the egg situation if it is unable to do the required lookup during init. 
<pre>
# ./magan-go-linux-amd64 
Sun Apr 21 12:44:49 2019 Magan[25404] Magan/1.2.8g
Sun Apr 21 12:44:49 2019 Magan[25404] Port :53
Sun Apr 21 12:44:49 2019 Magan[25404] Ready!
Sun Apr 21 12:44:56 2019 Magan[25404] UDP Recvd 32 bytes from 127.0.0.1:54952
Error: Get https://dns.google.com/resolve?name=dns.google.com.&type=AAAA: dial tcp: lookup dns.google.com on 127.0.0.1:53: read udp 127.0.0.1:54952->127.0.0.1:53: i/o timeout
Error: Get https://dns.google.com/resolve?name=dns.google.com.&type=A: dial tcp: lookup dns.google.com on 127.0.0.1:53: read udp 127.0.0.1:54952->127.0.0.1:53: i/o timeout
2019/04/21 12:45:01 Get https://dns.google.com/resolve?name=dns.google.com.&type=AAAA: dial tcp: lookup dns.google.com on 127.0.0.1:53: read udp 127.0.0.1:54952->127.0.0.1:53: i/o timeout
2019/04/21 12:45:01 Get https://dns.google.com/resolve?name=dns.google.com.&type=A: dial tcp: lookup dns.google.com on 127.0.0.1:53: read udp 127.0.0.1:54952->127.0.0.1:53: i/o timeout
</pre>

One workaround is to start magan after [`update_etc_hosts_dns_google.sh`](https://github.com/evuraan/Magan/blob/master/scripts/update_etc_hosts_dns_google.sh) finishes:

<pre>
$ sudo ./update_etc_hosts_dns_google.sh 
$ sudo magan-go-linux-amd64
</Pre>

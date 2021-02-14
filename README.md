# Magan

Magan is a DNS over HTTPS ([DoH](https://en.wikipedia.org/wiki/DNS_over_HTTPS)) server. 

DNS dates back to the gentler days of Internet when clear text transmissions were considered quite OK. These days, there is increasing awareness among users to encrypt their traffic, including DNS. 

**Magan** handles your incoming DNS requests and retrieves appropriate responses from [Google Public DNS](https://developers.google.com/speed/public-dns/docs/dns-over-https) over HTTPS - thereby encrypting your otherwise clear-text DNS traffic.

The [C](https://github.com/evuraan/Magan/blob/master/src/magan.c) version is recommended; also available are the [Go](https://github.com/evuraan/Magan/blob/master/src/magan_go.go)  and [Python3](https://github.com/evuraan/Magan/blob/master/src/magan.py) variants. 

A few pre-built binaries for Linux and Windows are available [here](https://github.com/evuraan/Magan/tree/master/bin).

See  [here](https://github.com/evuraan/Magan/tree/master/bin) for running Magan as a Windows OS Service. 

## Build instructions

### The C version


We need `libcurl4-openssl-dev` and `libjson-c`, usually installed on Debian thusly:
<pre>
$ sudo apt install libjson-c libcurl4-openssl-dev
</pre>
or, try <pre>
$ sudo apt install libjson-c-dev libcurl4-openssl-dev 
</pre>
Once all the pre-requisites are met, compile magan as:
<pre>
$ gcc -Wall -Wvla -Wextra magan.c -pthread -lcurl -ljson-c -o magan-$(uname -m) 
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

## Changelog

See [Changelog](./Changelog.md)

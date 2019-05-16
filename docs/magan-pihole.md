# Configuring Magan for Pi-hole

I've been requested for a How-To on configuring **Magan** as a DNS-Over-HTTPS server for Pi-hole. 

In this guide, we'd be setting up Magan as `$HOME/magan/magan` listening on port **5053**. We also assume that you have Pi-hole installed and running - if not, please follow [this excellent guide](https://docs.pi-hole.net/) to setup Pi-hole.

## Step 1: Install Magan 

**Magan** has three flavors to choose from, the [C](https://github.com/evuraan/Magan/blob/master/src/magan.c) version is recommended; also available are the [Go](https://github.com/evuraan/Magan/blob/master/src/magan_go.go)  and [Python3](https://github.com/evuraan/Magan/blob/master/src/magan.py) variants. A few pre-built binaries for Linux and Windows are available [here](https://github.com/evuraan/Magan/tree/master/bin).

Installing the **C** Version:

<pre>
$ sudo apt install libjson-c libcurl4-openssl-dev
$ mkdir $HOME/magan && cd $HOME/magan
$ wget https://github.com/evuraan/Magan/raw/master/src/magan.c -O magan.c 
$ gcc  magan.c -pthread -lcurl -ljson-c -o magan
</pre>
For Go and Python variants, [see install instructions.](https://github.com/evuraan/Magan#build-instructions) 

To quickly verify your progress so far:

<pre>
$ $HOME/magan/magan --help
Wed May 15 20:33:27 2019 Magan[3871]: Magan/1.3.4c Copyright (C) 2019 Evuraan <evuraan@gmail.com>
Wed May 15 20:33:27 2019 Magan[3871]: This program comes with ABSOLUTELY NO WARRANTY.
Usage: 
  -h  --help         print this usage and exit
  -p  --port         alternate port to listen
  -d  --debug        show debug info
  -v  --version      print version information and exit
</pre>



## Step 2: Setup Magan 

Let's keep things super simple:
<pre>
$ sudo cp /etc/crontab /etc/$RANDOM-backup-crontab -v 
$ echo "*/2 * * * *    $(whoami) $HOME/magan/magan -p 5053 1>/dev/null 2>/dev/null || :"  | sudo tee -a /etc/crontab

</pre>
With this, you have your `/etc/crontab` manage the upkeep of magan every two minutes. 

To verify, wait about two minutes and try a simple query:
<pre>
$  dig @127.0.0.1 -p 5053 cnn.com

; <<>> DiG 9.10.3-P4-Raspbian <<>> @127.0.0.1 -p 5053 cnn.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9224
;; flags: qr aa rd ra ad; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;cnn.com.			IN	A

;; ANSWER SECTION:
cnn.com.		22	IN	A	151.101.65.67
cnn.com.		22	IN	A	151.101.193.67
cnn.com.		22	IN	A	151.101.129.67
cnn.com.		22	IN	A	151.101.1.67

;; Query time: 18 msec
;; SERVER: 127.0.0.1#5053(127.0.0.1)
;; WHEN: Wed May 15 20:24:28 PDT 2019
;; MSG SIZE  rcvd: 117
</pre> 
## Step 3: Configure Pi-hole
Finally, configure Pi-hole to use your **Magan** as the upstream DNS server:
<img src="https://docs.pi-hole.net/images/DoHConfig.png">

Don't forget to hit Return or click on Save. 

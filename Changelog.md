# Change Log 
All notable changes to this project will be documented in this file.


## Feb 13, 2021 
* C Variant updated to 2.0g.  
 - thread pool for udp connections
 - tcp connections to use `epoll()`
 - security enhancements
 - added Caching mechanism 
 
## Mar 02, 2021
- Go Variant gets caching. 
- C Variant: Bug fix with MX, SOA records. 
## Mar 03, 2021
- C and Go variants now can do `recursive` queries. <br>To test, `dig npr.org @192.168.1.1 +trace`. Replace `192.168.1.1` with your Magan's address. 

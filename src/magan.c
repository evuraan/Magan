/*
 * ----------------------------------------------------------------------------
    magan : a DoH server
    Copyright (C) 2021  Evuraan, <evuraan@gmail.com> 

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * ----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <curl/curl.h>
#include <stdint.h>
#include <fcntl.h>
#include <endian.h>
#include <json-c/json.h>
#include <getopt.h>
#include <stdarg.h>
#include <sys/epoll.h>

#define bufsize 8192
#define ONE_K 1024
#define PORT 53
#define UDP_THREADS 4
#define EPOLL_MAXEVENTS 10
#define CACHE_MAX_ITEMS 100
#define CACHE_STALE 5*60	// seconds
#define VAL1 1331
#define VAL2 441
#define DISABLE_CACHE 0

struct udp_sender_thread_thingy {
	int server_socket;
	char *buffer;
	struct sockaddr_in remoteaddr;
	int addrlen;
	int cut_here;
};

#pragma pack(push, 1)
struct tcp {
	uint16_t length;
};
#pragma pack(pop)

struct reply {
	size_t sendSize;
	char *sendThis;
};

#pragma pack(push, 1)
struct dns_header {
	uint16_t id;
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t qr:1;
	uint16_t opcode:4;
	uint16_t aa:1;
	uint16_t tc:1;
	uint16_t rd:1;
	uint16_t ra:1;
	uint16_t zero:3;
	uint16_t rcode:4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t rd:1;
	uint16_t tc:1;
	uint16_t aa:1;
	uint16_t opcode:4;
	uint16_t qr:1;
	uint16_t rcode:4;
	uint16_t zero:3;
	/*
	   uint16_t cd :1; // Checking Disabled (DNSSEC only; disables checking at the receiving server)
	   uint16_t ad :1; // Authenticated Data (for DNSSEC only; indicates that the data was authenticated)
	   uint16_t z :1; // Reserved for future use Must be zero in all queries
	 */
	uint16_t ra:1;
#else
#error "Adjust your <bits/endian.h> defines"
#endif
	uint16_t qdcount;	/* question count */
	uint16_t ancount;	/* Answer record count */
	uint16_t nscount;	/* Name Server (Autority Record) Count */
	uint16_t arcount;	/* Additional Record Count */
};
#pragma pack(pop)

#pragma pack(push, 1)
struct dns_question {
	uint16_t type;
	uint16_t class;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct dns_rr {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
};
#pragma pack(pop)

struct Node {
	CURL *handle;
	pthread_mutex_t *NodeMutex;
	int TimeStamp;
	struct curl_slist *slist;
	int TimeDelta;
	int Count;
	int UsageFlag;
	char *myslist_text;
	struct MemoryStruct *Chunky;
	struct Node *Next;
};

struct LinkedList {
	struct Node *HeadNode;
	struct Node *TailNode;
	int LLSize;
};

struct MemoryStruct {
	char *memory;
	size_t size;
};

struct cacheStruct {
	int key;
	int epoch;
	size_t len;
	char hit[bufsize];
};

// all them global variables
static struct LinkedList *Roller;
static struct Node *UseThisNode = 0;
char resolv_this[] = "dns.google.com";
char use_ns[] = "8.8.8.8";
static char holdmine[bufsize] = { 0 };

static int flashed = 0;
const int ttl_max = 597;
curl_version_info_data *curl_version_data;
char getter_url[] = "https://dns.google.com/";
int pid;
char Name[] = "Magan";
char Version[] = "Magan/2.0g epoll+pool+cache";
int LISTEN_PORT = 53;
int debug = 0;
pthread_t udpWorkers[UDP_THREADS] = { 0 };
int udpPipe[2] = { 0 };
struct cacheStruct cache[CACHE_MAX_ITEMS] = { 0 };

int sockfd = 0;

int epollFD = 0;
struct epoll_event epevent = { 0 };
struct epoll_event events[EPOLL_MAXEVENTS] = { 0 };

pthread_mutex_t cacheMutex = PTHREAD_MUTEX_INITIALIZER;

//prototypes here
char *getCacheEntry(char *url);
int doCurlStuff(char *url, char *json_buffer);
struct cacheStruct *cacheLookup(char *url);
struct cacheStruct *findValidHash(int key);
int get_hash(char *input);
void *udp_listener_thread(void *vargp);
int WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
void read_back(char *label_in, int len, char *buffer);
void *tcp_listener(void *vargp);
void get_reply(char *request, int PROTO, struct reply *reply, int cut_here);
int get_random();
void convert(char *dns, char *host);
void do_lookup(char *resolv_this_input, char *dns_server_input, int Query_Type, char *hold_here);
void setup_holdmine();
char *get_currentTime();
int PopulateList(struct LinkedList *Roller, int slot);
void Prep_HANDLE(struct Node *Node);
int WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
struct Node *get_CURLHANDLE();
void findNthWord(char *line_in, int n, char *word);
void init();
void show_usage();
void *send_udp_response(void *vargp);
int debug_print(char *format, ...);
int print(char *format, ...);
void *udpWorker(void *vargp);
int acceptNewConn();
//int populateCache(char *url, char *memory, int *chunkSize);
int populateCache(char *url, char *memory, uint chunkSize);
void handleTCPClient(int newSock);
int insertCacheEntry(struct cacheStruct *placeHere, char *memory, uint * chunkSize, int *keyPtr);

int main(int argc, char *argv[]) {

	pid = getpid();

	int c = 1;

	print("%s Copyright (C) 2021 Evuraan <evuraan@gmail.com>\n", Version);
	print("This program comes with ABSOLUTELY NO WARRANTY.\n");
	while (c) {

		static struct option long_options[] = {
			{"port", required_argument, NULL, 'p'},
			{"artist", required_argument, NULL, 'a'},
			{"help", no_argument, NULL, 'h'},
			{"debug", no_argument, NULL, 'd'},
			{"version", no_argument, NULL, 'v'},
			{NULL, 0, NULL, 0}
		};

		int option_index = 0;

		c = getopt_long(argc, argv, "p:hvd", long_options, &option_index);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'p':
			;
			char *ptr_alt_port;
			LISTEN_PORT = strtod(optarg, &(ptr_alt_port));
			if ((LISTEN_PORT <= 0) || (LISTEN_PORT > 65535)) {
				fprintf(stderr, "%s %s[%d]: Invalid alternate port, exiting.\n", get_currentTime(), Name, pid);
				return 1;
			}

			break;
		case 'h':
		case '?':
			show_usage();
			return 1;
			break;
		case 'd':
			debug++;
			debug_print("Debug set\n");
			break;

		case 'v':
			printf("Version: %s\n", Version);
			return 1;
			break;
		default:
			printf("?? getopt returned character code 0%o ??\n", c);
			show_usage();
			return 1;
			break;
		}

	}

	printf("%s %s[%d]: Listening on port: %d\n", get_currentTime(), Name, pid, LISTEN_PORT);

	pthread_t udp, tcp = { 0 };

	//tcp listener
	int tcp_rc = pthread_create(&tcp, NULL, tcp_listener, NULL);
	assert(tcp_rc == 0);

	//udp_listener();
	int udp_rc = pthread_create(&udp, NULL, udp_listener_thread, NULL);
	assert(udp_rc == 0);

	usleep(50);

	// launch udp thread workers
	// init udp Pipes:
	if (pipe(udpPipe) < 0) {
		perror("pipe err\n");
		exit(1);
	}
	// spawn worker threads:
	int rc, worker = 0;
	for (int i = 0; i < (UDP_THREADS - 1); i++) {
		debug_print("Launching udp worker: %d\n", worker++);
		rc = pthread_create(&udpWorkers[i], 0, udpWorker, 0);
		if (rc) {
			printf("Failed launching worker: %d\n", i);
		}
	}

	// become the last udp worker, instead of idling around:
	debug_print("Launching udp worker: %d\n", worker++);
	udpWorker(0);

	pthread_join(udp, NULL);

	return 0;
}

void show_usage() {
	printf("Usage: \n");
	printf("  -h  --help         print this usage and exit\n");
	printf("  -p  --port         alternate port to listen\n");
	printf("  -d  --debug        show debug info\n");
	printf("  -v  --version      print version information and exit\n");
	_exit(1);
}

void *udpWorker(void *vargp) {
	(void)vargp;
	pthread_t tid = pthread_self();
	debug_print("[%s] worker %ld\n", __func__, tid);
	int n = 0;
	uintptr_t ptrAsInt = 0;
	struct udp_sender_thread_thingy *udp_sender_thread_thingy = 0;
	while (1) {
		udp_sender_thread_thingy = 0;
		ptrAsInt = 0;
		n = read(udpPipe[0], &ptrAsInt, sizeof(ptrAsInt));
		if (!n) {
			perror("worker read\n");
			continue;
		}

		if (!ptrAsInt) {
			perror("ptrAsInt null\n");
			continue;
		}

		udp_sender_thread_thingy = (struct udp_sender_thread_thingy *)ptrAsInt;
		send_udp_response(udp_sender_thread_thingy);
		debug_print("[%s] answered by worker thread %ld\n", __func__, tid);
	}
}

void init() {

	setbuf(stdout, NULL);

	char looking_for[8] = "https";
	if (memcmp(getter_url, looking_for, strnlen(looking_for, 8)) == 0) {
		// reasonably fair assumption to make in Dec 2019:
		snprintf(holdmine, ONE_K, "%s", "dns.google.com:443:8.8.4.4");
		setup_holdmine();
	} else {
		printf("Non https url, skipping setup_holdmine()\n");
	}

	Roller = calloc(1, sizeof(*Roller));
	curl_version_data = curl_version_info(CURLVERSION_NOW);

#if LIBCURL_VERSION_NUM >= 0x073800
	if (curl_version_data->version_num >= 0x073800) {
		CURLsslset result;
		result = curl_global_sslset((curl_sslbackend) 1, NULL, NULL);
		assert(result == CURLSSLSET_OK);
	} else {
		//printf("%s %s[%d]: Note: libcurl does not support CURLSSLBACKEND_OPENSSL et al\n",  get_currentTime(), Name, pid); 

	}
#else
#warning "libcurl version too old to set CURLSSLBACKEND_OPENSSL"
	//printf("%s %s[%d]: Note: libcurl does not support CURLSSLBACKEND_OPENSSL et al\n",  get_currentTime(), Name, pid); 
#endif

	curl_global_init(CURL_GLOBAL_ALL);
	PopulateList(Roller, 4);
	print("Ready..\n");
}

void *udp_listener_thread(void *vargp) {
	(void)vargp;
	int PROTO = SOCK_DGRAM;
	int server_socket = socket(AF_INET, PROTO, 0);
	if (server_socket < 0) {
		fprintf(stderr, "socket error");
		return NULL;
	}
	//bind
	struct sockaddr_in myaddr = { 0 };
	struct sockaddr_in remoteaddr = { 0 };
	uint addrlen = sizeof(remoteaddr);

	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = INADDR_ANY;
	myaddr.sin_port = htons(LISTEN_PORT);

	if (bind(server_socket, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
		fprintf(stderr, "bind error\n");
		perror("Failed at udp bind");
		_exit(1);
		return NULL;
	}

	init();

	// any allocations for the while True loop should happen out here
	uint recvlen = 0;
	uintptr_t ptrAsInt = 0;
	int n = 0;

	while (1) {

		n = 0;
		recvlen = 0;
		struct udp_sender_thread_thingy *udp_sender_thread_thingy = calloc(2, sizeof(struct udp_sender_thread_thingy));
		udp_sender_thread_thingy->addrlen = addrlen;
		udp_sender_thread_thingy->server_socket = server_socket;

		char *buffer = calloc(bufsize, sizeof(*buffer));
		recvlen = recvfrom(server_socket, buffer, bufsize, 0, (struct sockaddr *)&remoteaddr, &addrlen);
		debug_print("UDP Recvd %d bytes\n", recvlen);
		udp_sender_thread_thingy->buffer = buffer;
		udp_sender_thread_thingy->remoteaddr = remoteaddr;
		udp_sender_thread_thingy->cut_here = recvlen;
		ptrAsInt = (uintptr_t) udp_sender_thread_thingy;
		n = write(udpPipe[1], &ptrAsInt, sizeof(ptrAsInt));
		if (n) {
			debug_print("Sent %d bytes to workers PTr: %lu\n", n, ptrAsInt);
		} else {
			perror("Dispatch fail\n");
			//exit(1);
			free(udp_sender_thread_thingy->buffer);
			free(udp_sender_thread_thingy);
		}
	}

	pthread_exit(NULL);
}

void *send_udp_response(void *vargp) {

	struct timeval start, end = { 0 };
	long secs_used, micros_used;
	gettimeofday(&start, NULL);

	struct udp_sender_thread_thingy *udp_sender_thread_thingy = (struct udp_sender_thread_thingy *)vargp;
	int PROTO = SOCK_DGRAM;
	struct reply reply = { 0 };
	reply.sendSize = 0;
	char sendThis[bufsize] = { 0 };
	reply.sendThis = sendThis;
	get_reply(udp_sender_thread_thingy->buffer, PROTO, &reply, udp_sender_thread_thingy->cut_here);

	int sendlen = sendto(udp_sender_thread_thingy->server_socket, reply.sendThis, reply.sendSize, 0, (struct sockaddr *)&udp_sender_thread_thingy->remoteaddr, udp_sender_thread_thingy->addrlen);

	gettimeofday(&end, NULL);
	secs_used = (end.tv_sec - start.tv_sec);
	micros_used = ((secs_used * 1000000) + end.tv_usec) - (start.tv_usec);

	free(udp_sender_thread_thingy->buffer);
	free(udp_sender_thread_thingy);
	debug_print("%s %s[%d]: udp sendlen: %d bytes, took %lu microseconds\n", get_currentTime(), Name, pid, sendlen, micros_used);

	return 0;
}

void *tcp_listener(void *vargp) {
	(void)vargp;
	int PROTO = SOCK_STREAM;

	// Create socket first
	sockfd = socket(AF_INET, PROTO, 0);
	if (sockfd < 0) {
		perror("socket error\n");
		return NULL;
	}
	/* Second: Set socket options */
	int optval = 1;
	int sockopt_int = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (sockopt_int < 0) {
		perror("Failed at setsockopt");
		return NULL;
	}

	/* Third: Bind to the port */
	/* int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */
	struct sockaddr_in address = { 0 };
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(LISTEN_PORT);

	int bind_int = bind(sockfd, (struct sockaddr *)&address, sizeof(address));
	if (bind_int < 0) {
		perror("Failed at bind");
		_exit(1);
		return NULL;
	}

	/* Fourth : Listen
	   Mark sockfd as passive - so it can accept incoming connections
	 */
	if (listen(sockfd, 200) < 0) {
		perror("Failed at listen");
		return NULL;
	}
	// and then give every thing over to epoll to perform C10K magic!
	// epoll_create 
	if ((epollFD = epoll_create(1)) < 0) {
		perror("epoll_create failed");
		exit(1);
	}
	epevent.events = EPOLLIN;
	epevent.data.fd = sockfd;

	if (epoll_ctl(epollFD, EPOLL_CTL_ADD, sockfd, &epevent) < 0) {
		perror("epoll_ctl failed");
		exit(1);
	}

	int eventCount = 0;
	while ((eventCount = epoll_wait(epollFD, events, EPOLL_MAXEVENTS, -1)) > 0) {
		for (int i = 0; i < eventCount; i++) {
			if (events[i].events & EPOLLERR || events[i].events & EPOLLRDHUP || events[i].events & EPOLLHUP) {
				print("Closing: %d\n", events[i].data.fd);
				close(events[i].data.fd);
			} else if (events[i].events & EPOLLIN) {
				// incoming
				if (events[i].data.fd == sockfd) {
					// new connection - try accepting this.
					if (acceptNewConn() < 0) {
						perror("Error accepting new client");
					}
				} else {
					// Client is sending a req.
					handleTCPClient(events[i].data.fd);
				}
			}
		}
	}

	return 0;
}

int acceptNewConn() {
	struct sockaddr_in address = { 0 };
	int addrlen = sizeof(address);
	int clientSock = accept(sockfd, (struct sockaddr *)&address, (socklen_t *) & addrlen);
	if (debug > 0) {
		char somebuff[bufsize] = { 0 };
		inet_ntop(AF_INET, &address.sin_addr, somebuff, INET_ADDRSTRLEN);
		debug_print("[%s] Connection from %s, port %d\n", __func__, somebuff, ntohs(address.sin_port));
	}
	if (clientSock) {
		struct epoll_event epevent = { 0 };
		epevent.events = EPOLLIN | EPOLLRDHUP;
		epevent.data.fd = clientSock;
		if (epoll_ctl(epollFD, EPOLL_CTL_ADD, clientSock, &epevent) < 0) {
			perror("epoll_ctl failed accepting from a new client");
			shutdown(clientSock, SHUT_RDWR);
			close(clientSock);
			return -1;
		} else {
			debug_print("[%s] Added new connection %d to epoll\n", __func__, clientSock);
		}
	}
	return 0;
}

void handleTCPClient(int newSock) {
	if (!newSock) {
		return;
	}

	char ReadThis[bufsize] = { 0 };
	char sendThis[bufsize] = { 0 };

	struct timeval start, end = { 0 };
	gettimeofday(&start, 0);
	int n = read(newSock, ReadThis, bufsize);
	if (n <= 0) {
		return;
	}
	debug_print("TCP Recvd %d bytes\n", n);
	long secs_used, micros_used = 0;
	struct reply replyThing = {.sendSize = 0,.sendThis = sendThis };
	get_reply(ReadThis, SOCK_STREAM, &replyThing, n);

	int sendlen = send(newSock, replyThing.sendThis, replyThing.sendSize, 0);

	gettimeofday(&end, NULL);
	secs_used = (end.tv_sec - start.tv_sec);
	micros_used = ((secs_used * 1000000) + end.tv_usec) - (start.tv_usec);

	debug_print("%s %s[%d]: tcp sendlen: %d bytes, took %lu microseconds\n", get_currentTime(), Name, pid, sendlen, micros_used);
}

void read_back(char *label_in, int len, char *buffer) {
	char label[ONE_K] = { 0 };
	if (len > ONE_K) {
		len = ONE_K;
	}
	memcpy(&label, label_in, len);
	char *we_made = buffer;
	int labelVal = 0;
	for (int i = 1; i < len; i++) {
		labelVal = (int)label[i];
		if (labelVal == 192) {
			break;
		} else if (label[i] < 45) {
			we_made[i - 1] = '.';
		} else if ((labelVal >= 40) && (labelVal < 192)) {
			we_made[i - 1] = label[i];
		} else {
			we_made[i - 1] = 46;
		}
	}
	return;
}

// request is bufsize long 
void get_reply(char *request, int PROTO, struct reply *reply, int cut_here) {
	char *r = request;
	char *tcbuf = request;	// to send the tc goody if needed later

	struct tcp tcp = { 0 };
	uint16_t somenu = 0;
	if (PROTO == SOCK_STREAM) {
		//puts("Inching tcp header");
		memcpy(&somenu, r, sizeof(somenu));
		r += sizeof(tcp);
	}

	struct dns_header header = { 0 };
	memcpy(&header, r, sizeof(header));

	if ((header.opcode > 0) || (header.rcode > 0) || (ntohs(header.qdcount) != 1) || (ntohs(header.arcount) > 10) || (ntohs(header.nscount) > 10)) {
		printf("%s %s[%d]: Bad Query, QueryId: %d - outta here!\n", get_currentTime(), Name, pid, ntohs(header.id));
		reply->sendSize = 12;	// just to mess with, send back some junk from our side too..
		return;
	}

	r += sizeof(header);
	char *Question_start = r;

	int nlen = bufsize - (r - request);
	if (nlen < 0) {
		return;
	}
	//int end = find_null(r);
	int end = strnlen(r, nlen);

	char question[ONE_K] = { 0 };
	memcpy(&question, r, ONE_K);
	char readable[4096] = { 0 };
	read_back(question, end, readable);
	//printf("Question: %s\n", readable);

	end = strnlen(question, ONE_K);

	r += end + 1;
	struct dns_question dns_question = { 0 };
	memcpy(&dns_question, r, sizeof(dns_question));

	char Google_url[bufsize] = { 0 };
	snprintf(Google_url, bufsize, "%sresolve?name=%s&type=%d", getter_url, readable, ntohs(dns_question.type));

	//printf("Google_url: %s\n" , Google_url);
	debug_print("Url: %s\n", Google_url);

	int Question_Size = end + 1 + sizeof(dns_question);
	char Question[bufsize] = { 0 };

	memcpy(&Question, Question_start, Question_Size);
	//printf("for lols, question is %s\n", Question);

//--------------------------------------------------------------------------------------------------------------------------//

	char *R = reply->sendThis;
	int rcode = 0;
	struct dns_header reply_header = { 0 };
	memcpy(&reply_header, &header, sizeof(header));	// copy header from request,

	char awkward[bufsize] = { 0 };
	int gotData = 0;

	char *json_buffer = getCacheEntry(Google_url);
	if (!json_buffer) {
		if (doCurlStuff(Google_url, awkward)) {
			json_buffer = awkward;
			gotData++;
		}
	} else {
		gotData++;
	}

	if (gotData) {
		rcode = 0;
		reply_header.rcode = rcode;
		reply_header.ancount = 0;
		reply_header.arcount = 0;
		reply_header.nscount = 0;
		reply_header.qr = 1;
		reply_header.ra = 1;
	} else {
		rcode = 5;
		reply_header.rcode = 5;
		reply_header.ancount = htons(0);
		reply_header.arcount = 0;
		reply_header.nscount = 0;
		reply_header.qr = 1;
	}

	struct json_object *parsed_json_a, *parsed_json_b;
	struct json_object *Question_json;
	struct json_object *TC;
	struct json_object *AD;
	struct json_object *Answers;	// Answers - plural
	struct json_object *answer;	// holds the answer (singular) from Answers
	struct json_object *Comment;
	struct json_object *RA;
	struct json_object *CD;
	struct json_object *Status;
	struct json_object *RD;

	parsed_json_a = json_tokener_parse(json_buffer);
	json_object_object_get_ex(parsed_json_a, "Question", &Question_json);
	json_object_object_get_ex(parsed_json_a, "TC", &TC);
	json_object_object_get_ex(parsed_json_a, "AD", &AD);
	json_object_object_get_ex(parsed_json_a, "Answer", &Answers);
	json_object_object_get_ex(parsed_json_a, "Comment", &Comment);
	json_object_object_get_ex(parsed_json_a, "RA", &RA);
	json_object_object_get_ex(parsed_json_a, "CD", &CD);
	json_object_object_get_ex(parsed_json_a, "Status", &Status);
	json_object_object_get_ex(parsed_json_a, "RD", &RD);

	if (Answers == NULL) {

		reply_header.rcode = json_object_get_int(Status);
		debug_print("ancount 0 for %s, rcode is %d\n", readable, reply_header.rcode);

		reply_header.ancount = 0;
		// put changed header this into reply
		memcpy(R, &reply_header, sizeof(reply_header));	// <<<
		R += sizeof(reply_header);
		//copy over Question to response, 
		memcpy(R, &Question, Question_Size);	// <<<
		debug_print("Question_Size is %d\n", Question_Size);
		//R += Question_Size;
		reply->sendSize = sizeof(reply_header) + Question_Size;

	} else if (json_object_get_int(Status) != 0) {
		debug_print("Status is 0, Send rcode 2 or 5\n");
		reply_header.rcode = 2;

		// put changed header this into reply
		memcpy(R, &reply_header, sizeof(reply_header));	// <<<
		R += sizeof(reply_header);
		//copy over Question to response, 
		memcpy(R, &Question, Question_Size);	// <<<
		R += Question_Size;
		memcpy(R, &question, end);	// <<<
		R += (end + 1);
		reply->sendSize = sizeof(reply_header) + Question_Size + end + 1;

	} else {
		size_t answer_count, i;
		reply_header.aa = 1;
		answer_count = json_object_array_length(Answers);
		//printf("we got %lu answers\n", answer_count);
		reply_header.ancount = htons(answer_count);

		// put changed header this into reply
		memcpy(R, &reply_header, sizeof(reply_header));	// <<<
		R += sizeof(reply_header);

		/*

		   |###[ DNS Question Record ]###
		   |  qname     = 'www.cnn.com.'
		   |  qtype     = A
		   |  qclass    = IN // Question Size

		 */

		//copy over Question to response, 
		memcpy(R, Question, Question_Size);	// <<<
		R += Question_Size;
		memcpy(R, question, end);	// <<<
		reply->sendSize = sizeof(reply_header) + Question_Size;
		// int Question_Size = end + 1 + sizeof(dns_question) ;

		for (i = 0; i < answer_count; i++) {

			//printf("iter %ld \n " ,i);
			answer = json_object_array_get_idx(Answers, i);
			//printf(" We are here.. %lu : %s\n", i,json_object_get_string(answer) );
			parsed_json_b = json_tokener_parse(json_object_get_string(answer));
			struct json_object *name;
			struct json_object *type;
			struct json_object *TTL;
			struct json_object *data;

			json_object_object_get_ex(parsed_json_b, "name", &name);
			json_object_object_get_ex(parsed_json_b, "type", &type);
			json_object_object_get_ex(parsed_json_b, "TTL", &TTL);
			json_object_object_get_ex(parsed_json_b, "data", &data);
			int answer_type = json_object_get_int(type);

			char con_ns[bufsize] = { 0 };
			// general protection:
			int dataLen = json_object_get_string_len(name);
			if (!dataLen || dataLen > ONE_K) {
				continue;
			}
			char *interim_buf = (char *)json_object_get_string(name);
			convert(con_ns, interim_buf);
			int end_here = strnlen(con_ns, bufsize);

			memcpy(R, con_ns, end_here);
			R += end_here + 1;
			reply->sendSize += end_here + 1;

			// general protection:
			dataLen = json_object_get_string_len(data);
			if (!dataLen || dataLen > ONE_K) {
				continue;
			}

			if ((answer_type == 2) || (answer_type == 5) || (answer_type == 12)) {

				memset(con_ns, 0, bufsize);

				char *mehu = (char *)json_object_get_string(data);
				convert(con_ns, mehu);
				int nslen = strnlen(con_ns, bufsize) + 1;
				struct dns_rr dns_rr = { 0 };
				dns_rr.type = htons(answer_type);
				dns_rr.class = htons(1);
				dns_rr.ttl = htonl(json_object_get_int(TTL));
				dns_rr.rdlength = htons(nslen);

				memcpy(R, &dns_rr, sizeof(dns_rr));
				R += sizeof(dns_rr);
				reply->sendSize += sizeof(dns_rr);

				memcpy(R, con_ns, nslen);
				reply->sendSize += nslen;
				R += nslen;

			} else if ((answer_type == 99) || (answer_type == 16)) {
				memset(con_ns, 0, bufsize);
				int watermark = 255;
				char *mehu = (char *)json_object_get_string(data);

				int len = dataLen;
				char *mehu_ptr = mehu;
				char *con_ns_ptr = con_ns;

				if (len <= watermark) {
					con_ns[0] = len;
					for (int i = 0; i < len; i++) {
						con_ns[i + 1] = mehu[i];
					}
				} else {
					int x = len / watermark;
					int this_slice_len = 0;
					for (int i = 0; i < (x + 1); i++) {
						char mytemp[bufsize] = { 0 };
						char *mytemp_ptr = mytemp;
						if (i == 0) {
							// this slice is watermark long 
							this_slice_len = watermark;
						} else {
							// could this be another ginormous slice?
							int mehu_ptr_len = strnlen(mehu_ptr, ONE_K);
							if (mehu_ptr_len >= watermark) {
								this_slice_len = watermark;
							} else {
								this_slice_len = mehu_ptr_len;
							}
						}
						mytemp[0] = this_slice_len;
						mytemp_ptr += 1;
						memcpy(mytemp_ptr, mehu_ptr, this_slice_len);
						mytemp_ptr += this_slice_len;
						mehu_ptr += this_slice_len;
						memcpy(con_ns_ptr, mytemp, (1 + this_slice_len));
						con_ns_ptr += (1 + this_slice_len);
					}

				}

				int nslen = strnlen(con_ns, bufsize);
				struct dns_rr dns_rr = { 0 };
				dns_rr.type = htons(answer_type);
				dns_rr.class = htons(1);
				dns_rr.ttl = htonl(json_object_get_int(TTL));
				dns_rr.rdlength = htons(nslen);

				memcpy(R, &dns_rr, sizeof(dns_rr));
				R += sizeof(dns_rr);
				reply->sendSize += sizeof(dns_rr);

				memcpy(R, con_ns, nslen);
				reply->sendSize += nslen;
				R += nslen;

			} else if (answer_type == 15) {
				char *mehu = (char *)json_object_get_string(data);

				memset(con_ns, 0, bufsize);
				char scratch_text[ONE_K] = { 0 };
				findNthWord(mehu, 0, scratch_text);
				debug_print("prio scratch; %s\n", scratch_text);

				char *ptr;
				int priority_int = strtod(scratch_text, &(ptr));
				uint16_t priority = htons(priority_int);

				memset(scratch_text, 0, ONE_K);

				findNthWord(mehu, 1, scratch_text);
				convert(con_ns, scratch_text);
				int rdlen = sizeof(priority) + strnlen(con_ns, bufsize) + 1;

				struct dns_rr dns_rr = { 0 };
				dns_rr.type = htons(answer_type);
				dns_rr.class = htons(1);
				dns_rr.ttl = htonl(json_object_get_int(TTL));
				dns_rr.rdlength = htons(rdlen);

				memcpy(R, &dns_rr, sizeof(dns_rr));
				R += sizeof(dns_rr);

				memcpy(R, &priority, sizeof(priority));
				R += sizeof(priority);

				memcpy(R, con_ns, strnlen(con_ns, bufsize) + 1);
				R += strnlen(con_ns, bufsize) + 1;

				reply->sendSize += rdlen + sizeof(dns_rr);
			} else if (answer_type == 28) {

				//memset(con_ns, 0 , ONE_K); // we don't need it here

				char *mehu = (char *)json_object_get_string(data);

				struct sockaddr_in6 sa2 = { 0 };
				inet_pton(AF_INET6, mehu, &(sa2.sin6_addr));

				struct dns_rr dns_rr = { 0 };
				dns_rr.type = htons(answer_type);
				dns_rr.class = htons(1);
				dns_rr.ttl = htonl(json_object_get_int(TTL));
				dns_rr.rdlength = htons(sizeof(sa2.sin6_addr));

				memcpy(R, &dns_rr, sizeof(dns_rr));
				R += sizeof(dns_rr);

				memcpy(R, &sa2.sin6_addr, sizeof(sa2.sin6_addr));
				R += sizeof(sa2.sin6_addr);

				reply->sendSize += sizeof(sa2.sin6_addr) + sizeof(dns_rr);

			} else if (answer_type == 1) {

				//memset(con_ns, 0 , ONE_K);

				char *mehu = (char *)json_object_get_string(data);

				struct sockaddr_in sa = { 0 };
				inet_pton(AF_INET, mehu, &(sa.sin_addr));

				struct dns_rr dns_rr = { 0 };
				dns_rr.type = htons(answer_type);
				dns_rr.class = htons(1);
				dns_rr.ttl = htonl(json_object_get_int(TTL));
				dns_rr.rdlength = htons(sizeof(sa.sin_addr));

				memcpy(R, &dns_rr, sizeof(dns_rr));
				R += sizeof(dns_rr);

				memcpy(R, &sa.sin_addr, sizeof(sa.sin_addr));
				R += sizeof(sa.sin_addr);

				reply->sendSize += sizeof(sa.sin_addr) + sizeof(dns_rr);

			} else if (answer_type == 6) {

				//memset(con_ns, 0 , ONE_K);

				char *mehu = (char *)json_object_get_string(data);
				// data: ns1.google.com. dns-admin.google.com. 240756130 900 900 1800 60

				char MNAME[ONE_K] = { 0 };
				char RNAME[ONE_K] = { 0 };

				char MNAME_raw[ONE_K] = { 0 };
				char RNAME_raw[ONE_K] = { 0 };
				char SERIAL_char[ONE_K] = { 0 };
				char REFRESH_char[ONE_K] = { 0 };
				char RETRY_char[ONE_K] = { 0 };
				char EXPIRE_char[ONE_K] = { 0 };
				char MINIMUM_char[ONE_K] = { 0 };

				findNthWord(mehu, 0, MNAME_raw);
				findNthWord(mehu, 1, RNAME_raw);
				findNthWord(mehu, 2, SERIAL_char);
				findNthWord(mehu, 3, REFRESH_char);
				findNthWord(mehu, 4, RETRY_char);
				findNthWord(mehu, 5, EXPIRE_char);
				findNthWord(mehu, 6, MINIMUM_char);

				convert(MNAME, MNAME_raw);
				convert(RNAME, RNAME_raw);

				char *ptr;
				int temp_int;
				temp_int = strtod(SERIAL_char, &(ptr));
				debug_print("temp_int: %d\n", temp_int);
				uint32_t SERIAL = htonl(temp_int);

				temp_int = strtod(REFRESH_char, &(ptr));
				debug_print("temp_int: %d\n", temp_int);
				uint32_t REFRESH = htonl(temp_int);

				temp_int = strtod(RETRY_char, &(ptr));
				debug_print("temp_int: %d\n", temp_int);
				uint32_t RETRY = htonl(temp_int);

				temp_int = strtod(EXPIRE_char, &(ptr));
				debug_print("temp_int: %d\n", temp_int);
				uint32_t EXPIRE = htonl(temp_int);

				temp_int = strtod(MINIMUM_char, &(ptr));
				debug_print("temp_int: %d\n", temp_int);
				uint32_t MINIMUM = htonl(temp_int);

				int rdlen = strnlen(MNAME, ONE_K) + 1 + strnlen(RNAME, ONE_K) + 1 + (5 * sizeof(SERIAL));	//all of the above

				struct dns_rr dns_rr = { 0 };
				dns_rr.type = htons(answer_type);
				dns_rr.class = htons(1);
				dns_rr.ttl = htonl(json_object_get_int(TTL));
				dns_rr.rdlength = htons(rdlen);

				memcpy(R, &dns_rr, sizeof(dns_rr));
				R += sizeof(dns_rr);

				// append MNAME
				memcpy(R, MNAME, strnlen(MNAME, ONE_K) + 1);
				R += strnlen(MNAME, ONE_K) + 1;

				//RNAME now  RNAME now  
				memcpy(R, RNAME, strnlen(RNAME, ONE_K) + 1);
				R += strnlen(RNAME, ONE_K) + 1;

				// serial now
				memcpy(R, &SERIAL, sizeof(SERIAL));
				R += sizeof(SERIAL);

				// refresh 
				memcpy(R, &REFRESH, sizeof(REFRESH));
				R += sizeof(REFRESH);

				// RETRY 
				memcpy(R, &RETRY, sizeof(RETRY));
				R += sizeof(RETRY);

				// EXPIRE
				memcpy(R, &EXPIRE, sizeof(EXPIRE));
				R += sizeof(EXPIRE);

				//MINIMUM  
				memcpy(R, &MINIMUM, sizeof(MINIMUM));
				R += sizeof(MINIMUM);

				reply->sendSize += sizeof(dns_rr) + rdlen;

			}
			json_object_put(parsed_json_b);
		}
	}
	json_object_put(parsed_json_a);

//--------------------------------------------------------------------------------------------------------------------------//

	if (debug > 0) {
		debug_print("Our response contains\n");
		debug_print(" -->  %d Query id.\n", ntohs(header.id));

		debug_print(" -->  %d qr \n", (reply_header.qr));
		debug_print(" -->  %d opcode \n", (reply_header.opcode));
		debug_print(" -->  %d aa \n", (reply_header.aa));
		debug_print(" -->  %d tc \n", (reply_header.tc));
		debug_print(" -->  %d rd \n", (reply_header.rd));
		debug_print(" -->  %d ra \n", (reply_header.ra));
		//debug_print(" -->  %d zero \n", (reply_header.zero) );
		debug_print(" -->  %d rcode \n", (reply_header.rcode));

		debug_print(" -->  %d Answers.\n", ntohs(reply_header.ancount));
		debug_print(" -->  %d qdcount.\n", ntohs(reply_header.qdcount));
		debug_print(" -->  %d arcount.\n", ntohs(reply_header.arcount));
		debug_print(" -->  %d nscount.\n", ntohs(reply_header.nscount));
	}

	if (PROTO == SOCK_STREAM) {

		uint16_t tcp = htons(reply->sendSize);
		char newSendy[bufsize] = { 0 };
		char *bleh = newSendy;
		memcpy(bleh, &tcp, sizeof(tcp));
		bleh += sizeof(tcp);
		memcpy(bleh, reply->sendThis, reply->sendSize);
		reply->sendSize += sizeof(tcp);

		memcpy(reply->sendThis, newSendy, reply->sendSize);
		return;
	} else {

		if (reply->sendSize >= 512) {
			print("Too Big: %lu bytes, sending the tc flag to query %d \n", reply->sendSize, ntohs(header.id));
			memset(reply->sendThis, 0, bufsize);	// wipe it clean
			char *R = reply->sendThis;

			struct dns_header tc_header = { 0 };
			memcpy(&tc_header, tcbuf, sizeof(tc_header));
			tc_header.qr = 1;
			tc_header.tc = 1;

			memcpy(R, &tc_header, sizeof(tc_header));
			reply->sendSize = sizeof(tc_header);
			R += sizeof(tc_header);
			tcbuf += sizeof(tc_header);

			int whatsleft = cut_here - sizeof(tc_header);
			if (whatsleft > 0) {
				memcpy(R, tcbuf, whatsleft);
				reply->sendSize += whatsleft;
			}

			return;

		} else {
			return;
		}
	}

}

int get_random() {

	int ret = 0;
	char *rfile = "/dev/urandom";
	int randfd = open(rfile, O_RDONLY);
	read(randfd, &ret, sizeof(ret));
	close(randfd);

	if (ret > 0) {
		return ret;
	} else {
		return abs(ret);
		// abs or this below
		//ret = -ret;
		//return ret;
	}
}

void do_lookup(char *resolv_this_input, char *dns_server_input, int Query_Type, char *hold_here) {

	int client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (client_socket < 0) {
		perror("client_socket error\n");
		return;
	}

	char *resolv_this = resolv_this_input;
	char *dns_server = dns_server_input;

	char buffer[4096] = { 0 };
	char *p = buffer;

	int scratch = 0;
	struct sockaddr_in server_address = { 0 };

	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(PORT);
	server_address.sin_addr.s_addr = inet_addr(dns_server);
	uint server_address_len = sizeof(server_address);

	struct dns_header header_thingy = { 0 };
	struct dns_header *header = &header_thingy;
	header->id = htons(get_random());
	header->rd = 1;
	header->qdcount = htons(1);
	int header_size = sizeof(struct dns_header);
	memcpy(p, header, header_size);
	//debug_print("header size is %d\n", header_size);

	p += header_size;

	char *alavalathi = calloc(ONE_K, sizeof(*alavalathi));
	convert(alavalathi, resolv_this);

	int qname_size = strnlen(alavalathi, ONE_K) + 1;
	memcpy(p, alavalathi, qname_size);
	p[qname_size] = 0;

	char readable[bufsize] = { 0 };
	read_back(p, strnlen(alavalathi, ONE_K), readable);
	//debug_print("Question: %s\n", readable);

	free(alavalathi);
	p += qname_size;	// <- we moved to the label section

	struct dns_question question = { 0 };
	int question_size = sizeof(question);
	question.type = htons(Query_Type);
	question.class = htons(Query_Type);

	//debug_print("Question size: %d\n", question_size );
	memcpy(p, &question, question_size);

	int oursize = question_size + qname_size + header_size;

	char recvbuffer[bufsize] = { 0 };
	char reply[bufsize] = { 0 };
	int sendlen = sendto(client_socket, (char *)buffer, oursize, 0, (struct sockaddr *)&server_address, server_address_len);
	int recvlen = recvfrom(client_socket, recvbuffer, bufsize, 0, (struct sockaddr *)&server_address, &server_address_len);

	//debug_print("sendlen: %d\n", sendlen);
	debug_print("recvd %d\n", recvlen);
	memcpy(reply, &recvbuffer, bufsize / 2);
	char *r = recvbuffer;
	struct dns_header replyHeader = { 0 };
	memcpy(&replyHeader, r, sizeof(replyHeader));

	if (debug > 0) {
		debug_print("The response contains: \n");
		debug_print(" -->  %d Questions.\n", ntohs(replyHeader.qdcount));
		debug_print(" -->  %d Answers.\n", ntohs(replyHeader.ancount));
		debug_print(" -->  %d Authoritative Servers.\n", ntohs(replyHeader.nscount));
		debug_print(" -->  %d Additional Records.\n", ntohs(replyHeader.arcount));
		debug_print(" -->  %d Query id.\n", ntohs(replyHeader.id));
	}

	if (!ntohs(replyHeader.ancount)) {
		fprintf(stderr, "Error: ancount: %d\n", ntohs(replyHeader.ancount));
		_exit(1);
	}

	r += sendlen;

	//scratch = find_null(r);
	// r is originally bufsize long
	int nLen = bufsize - (r - recvbuffer);
	if (nLen < 0) {
		return;
	}

	scratch = strnlen(r, nLen);

	r += scratch;

	struct dns_rr rr = { 0 };
	struct in_addr in = { 0 };

	memcpy(&rr, r, sizeof(rr));
	//debug_print(" --> rr_TYPE %d\n", ntohs(rr.type) );
	//debug_print(" --> rr_CLASS %d\n", ntohs(rr.class) );
	//debug_print(" --> rr_TTL %d\n", ntohl(rr.ttl) );
	//debug_print(" --> rr_RDLENGTH %d\n", ntohs(rr.rdlength) );

	r += sizeof(rr);
	memcpy(&in.s_addr, r, sizeof(in.s_addr));
	//debug_print("\n --> %s\n", inet_ntoa(in));

	memcpy(hold_here, inet_ntoa(in), 512);
	return;

}

// limit incoming to ONE_K bytes long
void convert(char *dns, char *host_in) {
	char host[bufsize] = { 0 };
	memcpy(host, host_in, strnlen(host_in, ONE_K));
	strncat(host, ".", strnlen(host, bufsize / 2));
	int j = 0;
	char temp[bufsize] = { 0 };
	char peg[bufsize] = { 0 };
	for (uint i = 0; i < strnlen(host, bufsize); i++) {
		if (host[i] == '.') {
			peg[0] = j;
			strncat(dns, peg, bufsize);
			strncat(dns, temp, bufsize);
			j = 0;
			memset(temp, 0, bufsize);
		} else {
			temp[j] = host[i];
			j++;
		}
	}
}

void setup_holdmine() {
	debug_print("%s says hello!\n", __func__);
	char new_ip[512] = { 0 };
	do_lookup(resolv_this, use_ns, 1, new_ip);
	debug_print("dns.google.com is at: %s\n", new_ip);
	if (new_ip[0]) {
		flashed = (unsigned long)time(NULL);
		memset(holdmine, 0, ONE_K);
		snprintf(holdmine, ONE_K, "%s%s", "dns.google.com:443:", new_ip);
		debug_print("Updating holdmine to %s\n", holdmine);
		//printf("%s %s[%d]: Ready\n", get_currentTime(), Name, pid);
	} else {
		debug_print("Wierd Error 22.14\n");
	}
	debug_print("%s says bye!\n", __func__);
}

char *get_currentTime() {
	static char CurrentTime[2048];
	char *y = CurrentTime;
	time_t t;
	time(&t);
	strncpy(CurrentTime, ctime(&t), 1000);
	CurrentTime[strcspn(CurrentTime, "\r\n")] = 0;	// works for LF, CR, CRLF, LFCR, ...
	return y;
}

int PopulateList(struct LinkedList *Roller, int slot) {

	//setup_holdmine();

	for (int i = 0; i <= slot; i++) {
		struct Node *cNode = calloc(1, sizeof(*cNode));
		cNode->TimeStamp = 0;
		cNode->NodeMutex = calloc(1, sizeof(*cNode->NodeMutex));
		cNode->Count = 0;
		cNode->UsageFlag = 0;
		cNode->TimeDelta = 0;
		cNode->handle = NULL;
		cNode->myslist_text = calloc(ONE_K, sizeof(*cNode->myslist_text));
		snprintf(cNode->myslist_text, 100, "Blank/New");	// so we can print legit chars 
		cNode->slist = NULL;
		cNode->Chunky = malloc(sizeof(*cNode->Chunky));

		Prep_HANDLE(cNode);

		if (i == 0) {
			// We're on HeadNode
			//puts("We're on HeadNode");
			Roller->HeadNode = cNode;
			Roller->TailNode = cNode;
			Roller->LLSize++;
			cNode->Next = NULL;
		} else if (i == 1) {
			//printf(" %d We need to find our spot\n",i);
			struct Node *Prev = Roller->HeadNode;
			Prev->Next = cNode;
			cNode->Next = NULL;
			Roller->LLSize++;
			Roller->TailNode = cNode;
			Roller->TailNode->Next = Roller->HeadNode;
		} else {
			//printf(" %d We need to find our spot\n",i);
			struct Node *LastNode = Roller->TailNode;
			LastNode->Next = cNode;
			cNode->Next = NULL;
			Roller->LLSize++;
			Roller->TailNode = cNode;
			Roller->TailNode->Next = Roller->HeadNode;
		}
		//printf("%d LLSize: %d\n",i, Roller->LLSize);
	}

	return 0;
}

void Prep_HANDLE(struct Node *Node) {
	// brand new, lets set it up
	Node->handle = curl_easy_init();
	//Node->NodeMutex = malloc(sizeof(Node->NodeMutex) );
	pthread_mutex_init(Node->NodeMutex, NULL);

	Node->Chunky->memory = malloc(1);
	Node->Chunky->size = 0;

	curl_easy_setopt(Node->handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(Node->handle, CURLOPT_WRITEDATA, (void *)Node->Chunky);
	curl_easy_setopt(Node->handle, CURLOPT_ACCEPT_ENCODING, "");
	curl_easy_setopt(Node->handle, CURLOPT_USERAGENT, Version);
#if LIBCURL_VERSION_NUM >= 0x073E00
	if (curl_version_data->version_num >= 0x073E00) {
		curl_easy_setopt(Node->handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
	}
#else
#warning "libcurl version too old to set CURL_HTTP_VERSION_2TLS"
#endif

	int TimeNow = (unsigned long)time(NULL);
	int TimeDelta = TimeNow - flashed;

	if (TimeDelta > ttl_max) {
		printf("%s %s INITIAL: Doing lookup, as flashed is stale from %d seconds ago\n", __func__, get_currentTime(), TimeDelta);
		setup_holdmine();
	}

	if (holdmine[0]) {
		struct curl_slist *slist1 = Node->slist;
		slist1 = curl_slist_append(NULL, holdmine);
		curl_easy_setopt(Node->handle, CURLOPT_RESOLVE, slist1);
		memcpy(Node->myslist_text, holdmine, strnlen(holdmine, bufsize));
	} else {
		puts("------------ that failed ------------- ");
	}

	Node->TimeStamp = (unsigned long)time(NULL);
}

int WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {

	//printf("alikullancdcndc---------- \n");
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;
	char *ptr = realloc(mem->memory, mem->size + realsize + 10);
	if (ptr == NULL) {
		//printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	mem->memory = ptr;
	//printf("mem->memory is at %p\n", mem->memory );
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	ptr = NULL;
	return realsize;
}

struct Node *get_CURLHANDLE() {
	// static Node * UseThisNode;

	//pthread_mutex_lock(&mutex);
	if (UseThisNode == NULL) {
		UseThisNode = Roller->HeadNode;
	} else {
		UseThisNode = UseThisNode->Next;
	}
	//pthread_mutex_unlock(&mutex);
	return UseThisNode;

}

// max len: ONE_K
void findNthWord(char *line_in, int n, char *word) {

	// note: we decay, use another char * to slide and iterate.
	char *line = line_in;

	int i = 0;
	char delim[] = " ";
	char *Field = word;
	int _len = 0;
	char *LinePtr = strtok(line, delim);
	while (LinePtr) {
		_len = strnlen(LinePtr, ONE_K);
		if (i == n) {
			strncpy(Field, LinePtr, _len + 1);
			break;
		}

		i++;
		LinePtr = strtok(NULL, delim);
	}

	return;
}

int debug_print(char *format, ...) {
	if (debug > 0) {
		va_list arguments;
		va_start(arguments, format);
		char print_buffer[bufsize];
		snprintf(print_buffer, bufsize, "%s %s[%d]: %s Debug: %s", get_currentTime(), Name, pid, Version, format);
		int done = vfprintf(stdout, print_buffer, arguments);
		va_end(arguments);
		return done;
	} else {
		return 0;
	}
}

int print(char *format, ...) {
	// simple print
	va_list arguments;
	va_start(arguments, format);
	char print_buffer[bufsize];
	snprintf(print_buffer, bufsize, "%s %s[%d]: %s", get_currentTime(), Name, pid, format);
	int done = vfprintf(stdout, print_buffer, arguments);
	va_end(arguments);
	return done;
}
int get_hash(char *input) {
	if (!*input) {
		return 0;
	}

	int hashval = 0;
	int hash = VAL1;
	while (*input) {
		hash = (hash * VAL2) + *input++;
		hashval += hash;
	}
	return abs(hashval);
}

int insertCacheEntry(struct cacheStruct *placeHere, char *memory, uint * chunkSize, int *keyPtr) {
	if (!placeHere) {
		return 0;
	}
	// no other checks and mutex ops, as we are called from populateCache
	placeHere->key = *keyPtr;
	placeHere->epoch = (int)time(0);
	placeHere->len = *chunkSize;
	memset(placeHere->hit, 0, bufsize);
	memcpy(placeHere->hit, memory, *chunkSize);
	return *chunkSize;
}

int populateCache(char *url, char *memory, uint chunkSize) {
	if (DISABLE_CACHE) {
		return 0;
	}

	if (chunkSize > bufsize) {
		return 0;
	}

	if (!chunkSize) {
		return 0;
	}
	int key = get_hash(url);
	if (!key) {
		return 0;
	}

	struct cacheStruct *hit = findValidHash(key);

	int placed = 0;
	int slot = -1;
	int updated = 0;
	int replaced = -1;
	if (!hit) {
		// no hit, let's add this one.
		pthread_mutex_lock(&cacheMutex);
		for (int i = 0; i < CACHE_MAX_ITEMS; i++) {
			if (!cache[i].key) {
				// shove it in here.
				if (insertCacheEntry(&cache[i], memory, &chunkSize, &key)) {
					placed++;
					slot = i;
					break;
				}
			}
		}
		pthread_mutex_unlock(&cacheMutex);

		// find and then drop a stale entry, and insert ourselves here.
		if (!placed) {
			int staleEpoch = (int)time(0) - (CACHE_STALE);
			pthread_mutex_lock(&cacheMutex);
			for (int i = 0; i < CACHE_MAX_ITEMS; i++) {
				if (cache[i].epoch < staleEpoch) {
					if (insertCacheEntry(&cache[i], memory, &chunkSize, &key)) {
						placed++;
						replaced = i;
						break;
					}
				}
			}
			pthread_mutex_unlock(&cacheMutex);
		}

	} else {
		// hit is valid, we must update 
		pthread_mutex_lock(&cacheMutex);
		if (insertCacheEntry(hit, memory, &chunkSize, &key)) {
			placed++;
			updated++;
		}
		pthread_mutex_unlock(&cacheMutex);
	}

	if (debug) {
		if (!placed) {
			// what does this really mean?
			// we could not find a spot to fill in?
			debug_print("Cache too full, dropping key: %d for %s\n", key, url);
		}
		if (slot >= 0) {
			debug_print("Placed cache for %s key %d at %d\n", url, key, slot);
		}
		if (updated) {
			debug_print("Updated cache entry for %s key %d\n", url, key);
		}

		if (replaced >= 0) {
			debug_print("Replaced entry at %d for %s key %d\n", replaced, url, key);
		}
	}

	return placed;
}

struct cacheStruct *findValidHash(int key) {
	if (!key) {
		return 0;
	}
	struct cacheStruct *hit = 0;
	pthread_mutex_lock(&cacheMutex);
	for (int i = 0; i < CACHE_MAX_ITEMS; i++) {
		if (key == cache[i].key) {
			int now = (int)time(0);
			int stale = now - cache[i].epoch;
			if (stale > CACHE_STALE) {
				// hit, but stale.
				// wipe key and epoch clean
				cache[i].key = 0;
				cache[i].epoch = 0;
				cache[i].len = 0;
				break;
			} else {
				// valid, clean hit!
				hit = &cache[i];
				break;
			}
		}
	}
	pthread_mutex_unlock(&cacheMutex);
	return hit;
}

struct cacheStruct *cacheLookup(char *url) {
	int key = get_hash(url);
	if (!key) {
		return 0;
	}
	return findValidHash(key);
}

char *getCacheEntry(char *url) {
	if (DISABLE_CACHE) {
		return 0;
	}

	int key = get_hash(url);
	if (!key) {
		return 0;
	}
	struct cacheStruct *hit = findValidHash(key);
	if (hit) {
		if (!hit->len) {
			// too small.
			return 0;
		}
		if (hit->len > bufsize) {
			// too large.   
			return 0;
		}
		return hit->hit;
	}
	return 0;
}

int doCurlStuff(char *url, char *json_buffer) {

	int gotStuff = 0;
	uint fish = 0;
	struct Node *Node = get_CURLHANDLE();
	if (!Node) {
		fprintf(stderr, "get_CURLHANDLE returned null, this won't fly. Error 33\n");
		_exit(1);
	}
	debug_print("Node %p, handle %p, Usage: %d\n", Node, Node->handle, (Node->Count + 1));
	CURL *hnd = Node->handle;
	pthread_mutex_lock(Node->NodeMutex);
	Node->Count++;
	curl_easy_setopt(hnd, CURLOPT_URL, url);
	CURLcode res = curl_easy_perform(hnd);
	if (res == CURLE_OK) {
		populateCache(url, Node->Chunky->memory, Node->Chunky->size);
		memcpy(json_buffer, Node->Chunky->memory, Node->Chunky->size);
		fish = Node->Chunky->size;
		gotStuff++;
	}

	if (Node->Chunky->memory) {
		free(Node->Chunky->memory);
		Node->Chunky->memory = NULL;
	}
	if (Node->Chunky->size) {
		Node->Chunky->size = 0;
	}
	pthread_mutex_unlock(Node->NodeMutex);

	// now that we are outside the lock, print to console.
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		print("Curl attempt to %s failed\n", url);
	} else {
		debug_print("[%s] We GOT %lu bytes\n", __func__, fish);
	}

	return gotStuff;
}

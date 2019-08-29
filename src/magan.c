/*
 * ----------------------------------------------------------------------------
    magan : a DoH server
    Copyright (C) 2019  Evuraan, <evuraan@gmail.com> 

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


#define bufsize 8192
#define PORT 53


struct udp_sender_thread_thingy{
	int server_socket;
	char *buffer;
	struct sockaddr_in remoteaddr;
	int addrlen;
	int cut_here;
};



#pragma pack(push, 1)
struct tcp{
        uint16_t length;
};
#pragma pack(pop)


struct reply{
	size_t sendSize;
	char *sendThis;
};

#pragma pack(push, 1)
struct dns_header{
	uint16_t id;
# if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t qr:1;
	uint16_t opcode:4;
	uint16_t aa:1;
	uint16_t tc:1;
	uint16_t rd:1;
	uint16_t ra:1;
	uint16_t zero:3;
	uint16_t rcode:4;
# elif __BYTE_ORDER == __LITTLE_ENDIAN
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
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
	uint16_t qdcount;	/* question count */
	uint16_t ancount;	/* Answer record count */
	uint16_t nscount;	/* Name Server (Autority Record) Count */ 
	uint16_t arcount;	/* Additional Record Count */
} ;
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

struct Node{
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


struct LinkedList{
        struct Node *HeadNode;
        struct Node *TailNode;
        int LLSize;
};


struct MemoryStruct {
  char *memory;
  size_t size;
};


// all them global variables
static struct LinkedList *Roller;
static struct Node * UseThisNode = NULL;
char resolv_this[] = "dns.google.com";
char use_ns[] = "8.8.8.8";
static char holdmine[bufsize];
static int flashed = 0;
const int ttl_max = 597;
curl_version_info_data  *curl_version_data;
char getter_url[] = "https://dns.google.com/";
int pid;
char Name[] = "Magan";
char Version[] = "Magan/1.3.5c";
int LISTEN_PORT = 53;
int debug = 0;


//pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


//prototypes here
void *udp_listener_thread(void *vargp);
int WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
int find_null(char *some_word);
void read_back(char *label_in, int len, char *buffer);
void *tcp_listener(void *vargp);
void *HandleNewIncomingTCP(void *vargp);
void get_reply(char *request, int PROTO, struct reply *reply, int cut_here);
int get_random();
void convert(char *dns, char *host);
void do_lookup(char *resolv_this_input, char *dns_server_input, int Query_Type, char *hold_here);
void setup_holdmine();
char * get_currentTime();
int PopulateList(struct LinkedList *Roller, int slot);
void Prep_HANDLE(struct Node * Node);
int WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
struct Node * get_CURLHANDLE();
void findNthWord(char *line_in, int n, char *word);
void init();
void show_usage();
void *send_udp_response(void *vargp);
int debug_print(char *format, ...);
int print(char *format, ...);


int main(int argc, char *argv[]){

	pid = getpid();

        int c = 1;

	print("%s Copyright (C) 2019 Evuraan <evuraan@gmail.com>\n", Version);
	print("This program comes with ABSOLUTELY NO WARRANTY.\n");
	while (c){

		static struct option long_options[] = {
		    {"port", required_argument, NULL, 'p'},
		    {"artist", required_argument, NULL, 'a'},
		    {"help", no_argument, NULL, 'h'},
		    {"debug", no_argument, NULL, 'd'},
		    {"version", no_argument, NULL, 'v'},
		    {NULL, 0, NULL, 0}
		};

               int this_option_optind = optind ? optind : 1;
               int option_index = 0;


	       c = getopt_long(argc, argv, "p:hvd", long_options, &option_index);
	       if (c == -1){
                   break;
		}

		switch (c){
			case 'p':
				;
				char *ptr_alt_port;
				LISTEN_PORT = strtod(optarg, &(ptr_alt_port));
				if ( (LISTEN_PORT <= 0) || (LISTEN_PORT > 65535) ){
					fprintf(stderr, "%s %s[%d]: Invalid alternate port, exiting.\n",get_currentTime(), Name, pid);
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

	//udp_listener();
	pthread_t udp, tcp;
	int udp_rc = pthread_create(&udp, NULL, udp_listener_thread, NULL);
	assert(udp_rc == 0);

	sleep(1);
	int tcp_rc =  pthread_create(&tcp, NULL, tcp_listener, NULL);
        assert(tcp_rc == 0);


	sleep(3);
	pthread_join(udp, NULL);

	return 0;
}

void show_usage(){
	printf("Usage: \n");
	printf("  -h  --help         print this usage and exit\n");
	printf("  -p  --port         alternate port to listen\n");
	printf("  -d  --debug        show debug info\n");
	printf("  -v  --version      print version information and exit\n");
	_exit(1);
}


void init(){

        setbuf(stdout, NULL);

//char getter_url[] = "https://dns.google.com/";
	char looking_for[] = "https";
        if ( memcmp(getter_url, looking_for, strlen(looking_for) ) == 0) {
		setup_holdmine();
	} else {
		printf("Non https url, skipping setup_holdmine()\n");
	}

	Roller = calloc(1,sizeof(*Roller) );
	curl_version_data = curl_version_info(CURLVERSION_NOW);

#if LIBCURL_VERSION_NUM >= 0x073800
        if (curl_version_data->version_num >= 0x073800){
                CURLsslset result;
                result = curl_global_sslset((curl_sslbackend)1, NULL, NULL);
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
}



void *udp_listener_thread(void *vargp){
	int PROTO = SOCK_DGRAM;
	int server_socket = socket(AF_INET, PROTO,0);
	if (server_socket < 0){
		fprintf(stderr, "socket error");
		return NULL;
	}
	 
	//bind
	struct sockaddr_in myaddr;
	struct sockaddr_in remoteaddr;
	int addrlen = sizeof(remoteaddr);

        myaddr.sin_family = AF_INET;
        myaddr.sin_addr.s_addr = INADDR_ANY;
        myaddr.sin_port = htons(LISTEN_PORT);

	if ( bind(server_socket, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0){
		fprintf(stderr, "bind error\n");
		perror("Failed at udp bind");
		_exit(1);
		return NULL;
	}

	init();

	// any allocations for the while True loop should happen out here
	char sendThis[bufsize];
	int sendlen, recvlen;

	while (1){


		struct udp_sender_thread_thingy *udp_sender_thread_thingy = calloc(2,sizeof(struct udp_sender_thread_thingy) );
		udp_sender_thread_thingy->addrlen = addrlen;
		udp_sender_thread_thingy->server_socket = server_socket;

		char *buffer = calloc(bufsize, sizeof(*buffer) );
		recvlen = recvfrom(server_socket, buffer, bufsize, 0, (struct sockaddr *)&remoteaddr, &addrlen);
		print("UDP Recvd %d bytes\n" , recvlen);
		udp_sender_thread_thingy->buffer = buffer;
		udp_sender_thread_thingy->remoteaddr = remoteaddr;
		udp_sender_thread_thingy->cut_here = recvlen;
                pthread_t udp_responder;
    		pthread_attr_t attr;
    		pthread_attr_init(&attr);
		pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);

                int udp_t_rc = pthread_create(&udp_responder, &attr, send_udp_response, udp_sender_thread_thingy);
		//perror("udp_t_failed");
                //assert(udp_t_rc == 0);

		if (udp_t_rc != 0){
			perror("whoa! too many udp threads?");
			printf("%s %s[%d]: Adding 1usec sleep, since too many udp threads\n", get_currentTime(), Name, pid);
			usleep(1);
		}

	}

	pthread_exit(NULL);
}

void *send_udp_response(void *vargp){
        pthread_detach(pthread_self());

	struct timeval start, end;
    	long secs_used,micros_used;
	gettimeofday(&start, NULL);


	struct udp_sender_thread_thingy *udp_sender_thread_thingy = (struct udp_sender_thread_thingy *)vargp;
	int PROTO = SOCK_DGRAM;
	struct reply reply;
	reply.sendSize = 0;
	char sendThis[bufsize] = {0};
	reply.sendThis = sendThis;
	//get_reply(udp_sender_thread_thingy->buffer, PROTO, &reply);

	//memcpy(temp, udp_sender_thread_thingy->buffer, bufsize);
	//free(udp_sender_thread_thingy->buffer);
	//get_reply(temp, PROTO, &reply);
	get_reply(udp_sender_thread_thingy->buffer, PROTO, &reply , udp_sender_thread_thingy->cut_here);


	int sendlen = sendto(udp_sender_thread_thingy->server_socket,reply.sendThis,reply.sendSize , 0, (struct sockaddr *)&udp_sender_thread_thingy->remoteaddr, udp_sender_thread_thingy->addrlen);

	gettimeofday(&end, NULL);
	secs_used=(end.tv_sec - start.tv_sec);
	micros_used= ((secs_used*1000000) + end.tv_usec) - (start.tv_usec);

	free(udp_sender_thread_thingy->buffer); 
	free(udp_sender_thread_thingy);
	printf("%s %s[%d]: udp sendlen: %d bytes, took %lu microseconds\n", get_currentTime(), Name, pid, sendlen, micros_used );
        //printf(" ----- udp -----  Exiting %lu\n", pthread_self());
        pthread_exit(NULL);
}



void *tcp_listener(void *vargp){
	int PROTO = SOCK_STREAM;

	// Create socket first
	int sockfd =  socket(AF_INET, PROTO,0);
	if ( sockfd < 0 ){
		perror("socket error\n");
		return NULL;
	} else { 
		//printf("sockefd is %d\n", sockfd);
	}
        /* Second: Set socket options */
        int optval = 1;
        //int sockopt_int = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optval, sizeof(optval) );
        int sockopt_int = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR , &optval, sizeof(optval) );
        if ( sockopt_int < 0 ){
                perror("Failed at setsockopt");
                return NULL;
        } else {
                //printf("setsockopt succeeded\n");
        }

        /* Third: Bind to the port */
        /* int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */
        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(LISTEN_PORT);

        int bind_int = bind(sockfd, (struct sockaddr *)&address, sizeof(address)) ;
        //printf("bind_int ; %d\n", bind_int);
        if (bind_int < 0 ) {
                perror("Failed at bind");
                _exit(1);
                return NULL;
        } else {
                //printf("bind succeeded\n");
        }


        /* Fourth : Listen
           Mark sockfd as passive - so it can accept incoming connections
        */
        if ( listen(sockfd, 200) < 0 ) {
                perror("Failed at listen");
                return NULL;
        } else {
                //printf("listen succeeded\n");
        }

	print("Ready..\n");
	int addrlen = sizeof(address);

        while (1) {
                int newsocket = accept(sockfd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
		pthread_t tid;

 	        pthread_attr_t attr;
	        pthread_attr_init(&attr);
	        pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);


                //int rc = pthread_create(&tid, NULL, HandleNewIncomingTCP, &newsocket);
                int rc = pthread_create(&tid, &attr, HandleNewIncomingTCP, (void *)newsocket);
                //assert (rc == 0);
		if (rc != 0){
			perror("whoa! too many tcp threads?");
			printf("%s %s[%d]: Adding 1usec sleep, since too many tcp threads\n", get_currentTime(), Name, pid);
			usleep(1);
		}

	}

}


void *HandleNewIncomingTCP(void *vargp){
        pthread_detach(pthread_self());
        int newsocket = (int)vargp;

        char ReadThis[bufsize];
        char sendThis[bufsize];

	struct timeval start, end;
	long secs_used,micros_used;
	int n;
	int PROTO = SOCK_STREAM;
	struct reply reply;

	while(1){


		memset(ReadThis,0, bufsize);
                n = read(newsocket, ReadThis, 4096);
		gettimeofday(&start, NULL);

                if (n <= 0){
                        //printf("Breaking out of %d\n", newsocket);
                        break;
                }
		print("TCP Recvd %d bytes\n" , n);

		char *buffer = ReadThis;

                reply.sendSize = 0;
		memset(sendThis, 0, sizeof(sendThis) );
                reply.sendThis = sendThis;
                get_reply(buffer, PROTO, &reply,n);

                int sendlen = send(newsocket, reply.sendThis, reply.sendSize , 0);


		gettimeofday(&end, NULL);
		secs_used=(end.tv_sec - start.tv_sec);
		micros_used= ((secs_used*1000000) + end.tv_usec) - (start.tv_usec);

		printf("%s %s[%d]: tcp sendlen: %d bytes, took %lu microseconds\n", get_currentTime(), Name, pid, sendlen, micros_used );


		shutdown(newsocket,2);
        	close(newsocket);
	}
        //printf(" ----- tcp -----  Exiting %lu\n", pthread_self());
        pthread_exit(NULL);
}









int find_null(char *some_word){
	char This_word[4096] = {0};
        memcpy(This_word, some_word, strlen(some_word) );
        int i = 0;
        for (; i < 4096; i++){
                if (This_word[i] == 0){
                        //printf("Found null at %d\n", i);
                        break;
                } else {
                        //printf("%d is not null\n", i);
                        i++;
                }
        }

        return i;
}



void read_back(char *label_in, int len, char *buffer){

        char label[1024] = {0};
        memcpy(&label, label_in, 1024);
        char *we_made = buffer;
        //for (int i = 1; i <= (len - 1 ) ; i++){
        //for (int i = 1; i <= strlen(label) ; i++){
        //for (int i = 1; i <= (len - 1 ) ; i++){
        for (int i = 1; i < len ; i++){
                //printf("We got %d %d char: %c %p \n", i, label[i], label[i], label[i] );
                if ( label[i] == 192){
                        //printf("We hit 192\n");
                        break;
                } else if (  label[i] < 45){
                        //puts("Bindi!");
                         we_made[i-1] = '.';

                } else if ( label[i] >= 40 < 192 ){
                        //printf("We got %d %d char: %c %p \n", i, label[i], label[i], label[i] );
                        we_made[i-1] = label[i];
                } else {
                        //printf(".\n");
                        //printf(" -- ------ ---- We got %d %d char: %c %p \n", i, label[i], label[i], label[i] );
                        we_made[i-1] = 46 ;
                }
        }

        //strncat(we_made, ".", strlen(we_made) );

        return;
}



void get_reply(char *request, int PROTO, struct reply *reply, int cut_here){
	char *r = request;
	char *tcbuf = request; // to send the tc goody if needed later

	struct tcp tcp;
	uint16_t  somenu;
        if (PROTO == SOCK_STREAM){
                //puts("Inching tcp header");
		memcpy(&somenu, r, sizeof(somenu) );
                r += sizeof(tcp);
        }

	
	struct dns_header header;
	//memset(&header, 0, sizeof(header) );
	//printf("dns header request's is at %p\n", &header);
	memcpy(&header, r, sizeof(header) );

	/*
	if (strncmp( (char *)&header, r, sizeof(header)) == 0 ){
		printf("They are similar \n");
	} else {
		printf("They are NOT similar \n");
	}
	*/

	print(" -->  %d Query id.\n", ntohs(header.id) );
			
	//printf("\nThe request contains: \n");
	//printf(" -->  %d Query id.\n", ntohs(header.id) );
	/*
	print(" -->  %d Query id.\n", ntohs(header.id) );

	printf(" -->  %d qr \n", (header.qr) );
	printf(" -->  %d opcode \n", (header.opcode) );
	printf(" -->  %d aa \n", (header.aa) );
	printf(" -->  %d tc \n", (header.tc) );
	printf(" -->  %d rd \n", (header.rd) );
	printf(" -->  %d ra \n", (header.ra) );
	printf(" -->  %d rcode \n", (header.rcode) );

	printf(" -->  %d Answers.\n", ntohs(header.ancount) );
	printf(" -->  %d qdcount.\n", ntohs(header.qdcount) );
	printf(" -->  %d arcount.\n", ntohs(header.arcount) );
	printf(" -->  %d nscount.\n", ntohs(header.nscount) );

	print(" -->  %d Query id.\n", ntohs(header.id) );
	*/
		
        if ( ( header.opcode > 0) || ( header.rcode > 0) || ( ntohs(header.qdcount) != 1) || (ntohs(header.arcount) > 10) || (ntohs(header.nscount) > 10) ){
        	printf("%s %s[%d]: Bad Query, QueryId: %d - outta here!\n", get_currentTime(), Name, pid, ntohs(header.id));
		reply->sendSize = 12; // just to mess with, send back some junk from our side too..
		return;
        } 

	r += sizeof(header);
	char *Question_start = r;
	//printf("Question starts at %p %p\n", Question_start,r);

	int end = find_null(r);


	char question[1024] = {0};
	memcpy(&question, r, 1024);
	char readable[bufsize] = {0};
	read_back(question, end, readable);
	//printf("Question: %s\n", readable);

	end = strlen(question);

	r += end + 1;
	struct dns_question dns_question;
	memcpy(&dns_question, r, sizeof(dns_question) );
	//printf("qtype :%d\n", ntohs(dns_question.type) );
	//printf("class :%d\n", ntohs(dns_question.class) );

        //printf("%s %s[%d]: QueryId: %d, Question: %s, Type: %d\n", get_currentTime(), Name, pid, ntohs(header.id), readable, ntohs(dns_question.type) );

	char Google_url[bufsize] = {0};
	snprintf(Google_url, 4096, "%sresolve?name=%s&type=%d", getter_url,readable,ntohs(dns_question.type) );

	//printf("Google_url: %s\n" , Google_url);
	debug_print("Url: %s\n" , Google_url);  
	

	int Question_Size = end + 1 + sizeof(dns_question) ;
	char Question[bufsize] = {0};

	memcpy(&Question, Question_start,  Question_Size );
	//printf("for lols, question is %s\n", Question);

//--------------------------------------------------------------------------------------------------------------------------//

	char *R = reply->sendThis;
	int rcode = 0;
	struct dns_header reply_header; 
	memcpy(&reply_header, &header, sizeof(header) ); // copy header from request,
	char json_buffer[bufsize] = {0};
	
	// lets do the curl in here..
	struct Node *Node = get_CURLHANDLE();
	if (!Node){
		fprintf(stderr, "get_CURLHANDLE returned null, this won't fly. Error 33\n");
		_exit(1);
	}
	debug_print("Node %p, handle %p, Usage: %d\n", Node, Node->handle, (Node->Count + 1) );
	CURL *hnd = Node->handle;
	//printf("Mutex would be at %p\n", Node->NodeMutex);
	pthread_mutex_lock(Node->NodeMutex);
	Node->Count++;
        curl_easy_setopt(hnd, CURLOPT_URL, Google_url);
        CURLcode res = curl_easy_perform(hnd);
	if (res != CURLE_OK) {
		rcode = 5;
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		reply_header.rcode = 5;
		reply_header.ancount = htons(0);
		reply_header.arcount = 0;
		reply_header.nscount = 0;
		reply_header.qr = 1;

	} else {
		rcode = 0;
		debug_print("We GOT %lu bytes\n", Node->Chunky->size );      
		reply_header.rcode = rcode;
		reply_header.ancount = 0;
		reply_header.arcount = 0;
		reply_header.nscount = 0;
		reply_header.qr = 1;
		reply_header.ra = 1;
		memcpy(json_buffer, Node->Chunky->memory, Node->Chunky->size);
	}

	//printf("Freeing Node->Chunky->memory at %p\n", Node->Chunky->memory);
	free(Node->Chunky->memory);
	Node->Chunky->memory = NULL;
	Node->Chunky->size = 0;

	pthread_mutex_unlock(Node->NodeMutex);

	
        struct json_object *parsed_json_a , *parsed_json_b;
        struct json_object *Question_json;
        struct json_object *TC;
        struct json_object *AD;
        struct json_object *Answers; // Answers - plural
        struct json_object *answer; // holds the answer (singular) from Answers
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

	/*
        printf("Question: %s\n", json_object_get_string(Question_json) );
        printf("Status: %s\n", json_object_get_string(Status) );
        printf("Answers: %s\n", json_object_get_string(Answers) );
	*/

        if (Answers == NULL){
			
			reply_header.rcode = json_object_get_int(Status);
                        debug_print("ancount 0 for %s, rcode is %d\n", readable, reply_header.rcode);

			reply_header.ancount = 0;
			// put changed header this into reply
			memcpy(R, &reply_header, sizeof(reply_header) ); // <<<
			R += sizeof(reply_header);
			//copy over Question to response, 
			memcpy(R,&Question, Question_Size ); // <<<
			debug_print("Question_Size is %d\n", Question_Size ); 
			//R += Question_Size;
			reply->sendSize =  sizeof(reply_header) +   Question_Size;
			

        } else if  (json_object_get_int(Status) != 0 ){
                        debug_print("Status is 0, Send rcode 2 or 5\n");
			reply_header.rcode = 2;

			// put changed header this into reply
			memcpy(R, &reply_header, sizeof(reply_header) ); // <<<
			R += sizeof(reply_header);
			//copy over Question to response, 
			memcpy(R,&Question, Question_Size ); // <<<
			R += Question_Size;
			memcpy(R, &question, end  ); // <<<
			R +=  (end + 1);
			reply->sendSize =  sizeof(reply_header) +   Question_Size + end + 1;

        } else {
                size_t answer_count,i;
		reply_header.aa = 1;
                answer_count = json_object_array_length(Answers);
                //printf("we got %lu answers\n", answer_count);
		reply_header.ancount = htons(answer_count);

		// put changed header this into reply
		memcpy(R, &reply_header, sizeof(reply_header) ); // <<<
		R += sizeof(reply_header);

		/*
					
		   |###[ DNS Question Record ]###
		   |  qname     = 'www.cnn.com.'
		   |  qtype     = A
		   |  qclass    = IN // Question Size

		*/

		//copy over Question to response, 
        	memcpy(R,Question, Question_Size ); // <<<
		R += Question_Size;
		memcpy(R, question, end  ); // <<<
		reply->sendSize =  sizeof(reply_header) +   Question_Size ;
		// int Question_Size = end + 1 + sizeof(dns_question) ;

                for (i = 0; i < answer_count ; i++){

		
			//printf("iter %ld \n " ,i);
                        answer = json_object_array_get_idx(Answers, i);
                        //printf(" We are here.. %lu : %s\n", i,json_object_get_string(answer) );
                        parsed_json_b = json_tokener_parse(json_object_get_string(answer) );
                        struct json_object *name;
                        struct json_object *type;
                        struct json_object *TTL;
                        struct json_object *data;

                        json_object_object_get_ex(parsed_json_b, "name", &name);
                        json_object_object_get_ex(parsed_json_b, "type", &type);
                        json_object_object_get_ex(parsed_json_b, "TTL", &TTL);
                        json_object_object_get_ex(parsed_json_b, "data", &data);
			int answer_type = json_object_get_int(type) ;

			char con_ns[bufsize] = {0};
			char *interim_buf =  (char *)json_object_get_string(name) ;
			convert(con_ns, interim_buf);
			int end_here = strlen(con_ns) ;

			memcpy(R, con_ns, end_here);
			R += end_here + 1 ;
			reply->sendSize += end_here + 1;

			if ( ( answer_type == 2) ||  (answer_type == 5) || ( answer_type == 12)  ) {

                                memset(con_ns, 0 , bufsize);

				char *mehu = (char *)json_object_get_string(data);
				convert(con_ns, mehu);
				int nslen = strlen(con_ns) + 1;
				struct dns_rr dns_rr;
				dns_rr.type = htons(answer_type);
				dns_rr.class = htons(1);
				dns_rr.ttl = htonl(json_object_get_int(TTL) );
				dns_rr.rdlength = htons(nslen);

				memcpy(R, &dns_rr, sizeof(dns_rr) );
				R += sizeof(dns_rr) ;
				reply->sendSize += sizeof(dns_rr) ;

				memcpy(R, con_ns, nslen);
				reply->sendSize += nslen;
				R += nslen;

			} else if ( (answer_type == 99) ||  ( answer_type == 16 ) ){

                                memset(con_ns, 0 , bufsize);
				int watermark = 255;
				char *mehu = (char *)json_object_get_string(data);
				int len = strlen(mehu);
				char *mehu_ptr = mehu;
				char *con_ns_ptr = con_ns;
				
				if (len <= watermark ) {
					con_ns[0] = len;
					for (int i = 0; i < len; i++){
						con_ns[i + 1] = mehu[i];
					}
				} else { 
					int x = len / watermark;
					int this_slice_len = 0;
					for (int i = 0; i < (x + 1); i++){
						char mytemp[bufsize] = {0};
						char *mytemp_ptr = mytemp;
						if ( i == 0 ){
							// this slice is watermark long 
							this_slice_len = watermark;
						} else { 
							// could this be another ginormous slice?
							int mehu_ptr_len = strlen(mehu_ptr); // so we dont repeat strlen call
							if ( mehu_ptr_len >= watermark ){
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
						memcpy(con_ns_ptr, mytemp, (1 + this_slice_len) );
						con_ns_ptr += (1 + this_slice_len);
					}	

				}

				int nslen = strlen(con_ns);
				struct dns_rr dns_rr;
				dns_rr.type = htons(answer_type);
				dns_rr.class = htons(1);
				dns_rr.ttl = htonl(json_object_get_int(TTL) );
				dns_rr.rdlength = htons(nslen);

				memcpy(R, &dns_rr, sizeof(dns_rr) );
				R += sizeof(dns_rr) ;
				reply->sendSize += sizeof(dns_rr) ;

				memcpy(R, con_ns, nslen);
				reply->sendSize += nslen;
				R += nslen ;


			} else if ( answer_type == 15){

                                memset(con_ns, 0 , bufsize);


                                char *mehu = (char *)json_object_get_string(data);

				char scratch_text[512] = {0};
				findNthWord(mehu, 0, scratch_text);
				debug_print("prio scratch; %s\n", scratch_text);

				char *ptr;
				int priority_int = strtod(scratch_text, &(ptr));
				uint16_t priority = htons(priority_int);

				memset(scratch_text,0, 512);

				findNthWord(mehu, 1, scratch_text);
                                convert(con_ns, scratch_text);
				int rdlen = sizeof(priority) + strlen(con_ns) + 1;

                                struct dns_rr dns_rr;
				dns_rr.type = htons(answer_type);
                                dns_rr.class = htons(1);
                                dns_rr.ttl = htonl(json_object_get_int(TTL) );
                                dns_rr.rdlength = htons(rdlen);

                                memcpy(R, &dns_rr, sizeof(dns_rr) );
                                R += sizeof(dns_rr) ;

				memcpy(R, &priority, sizeof(priority)) ;
				R += sizeof(priority);

				memcpy(R, con_ns, strlen(con_ns) + 1 );
				R += strlen(con_ns) + 1 ;
				
                                reply->sendSize += rdlen + sizeof(dns_rr) ;
			} else if ( answer_type == 28 ) {


                                //memset(con_ns, 0 , 1024); // we don't need it here

                                char *mehu = (char *)json_object_get_string(data);

				struct sockaddr_in6 sa2;
				struct sockaddr_in sa;
				inet_pton(AF_INET6, mehu, &(sa2.sin6_addr)); 

		                struct dns_rr dns_rr;
				dns_rr.type = htons(answer_type);
                                dns_rr.class = htons(1);
                                dns_rr.ttl = htonl(json_object_get_int(TTL) );
                                dns_rr.rdlength = htons( sizeof(sa2.sin6_addr) ); 

                                memcpy(R, &dns_rr, sizeof(dns_rr) );
                                R += sizeof(dns_rr) ;

				memcpy(R, &sa2.sin6_addr, sizeof(sa2.sin6_addr) );   
				R += sizeof(sa2.sin6_addr)  ;
				
                                reply->sendSize += sizeof(sa2.sin6_addr) + sizeof(dns_rr);

			} else if ( answer_type == 1 ) {

				//memset(con_ns, 0 , 1024);

				
                                char *mehu = (char *)json_object_get_string(data);

				struct sockaddr_in sa;
				inet_pton(AF_INET, mehu, &(sa.sin_addr));  

		                struct dns_rr dns_rr;
				dns_rr.type = htons(answer_type);
                                dns_rr.class = htons(1);
                                dns_rr.ttl = htonl(json_object_get_int(TTL) );
                                dns_rr.rdlength = htons( sizeof(sa.sin_addr));

                                memcpy(R, &dns_rr, sizeof(dns_rr) );
                                R += sizeof(dns_rr) ;

				memcpy(R, &sa.sin_addr, sizeof(sa.sin_addr) );   
				R += sizeof(sa.sin_addr)  ;
				
                                reply->sendSize += sizeof(sa.sin_addr) + sizeof(dns_rr);


			} else if ( answer_type == 6 ) {

                                //memset(con_ns, 0 , 1024);

                                char *mehu = (char *)json_object_get_string(data);
				// data: ns1.google.com. dns-admin.google.com. 240756130 900 900 1800 60
	
				char MNAME[1024] = {0};
				char RNAME[1024] = {0};

				char MNAME_raw[1024] = {0};
				char RNAME_raw[1024] = {0};
				char SERIAL_char[1024] = {0};
				char REFRESH_char[1024] = {0};
				char RETRY_char[1024] = {0};
				char EXPIRE_char[1024] = {0};
				char MINIMUM_char[1024] = {0};

				findNthWord(mehu, 0, MNAME_raw);
				findNthWord(mehu, 1, RNAME_raw);
				findNthWord(mehu, 2, SERIAL_char);
				findNthWord(mehu, 3, REFRESH_char);
				findNthWord(mehu, 4, RETRY_char);
				findNthWord(mehu, 5, EXPIRE_char);
				findNthWord(mehu, 6, MINIMUM_char);

				convert(MNAME,MNAME_raw);
				convert(RNAME, RNAME_raw);

				char *ptr;
				int temp_int;
				temp_int = strtod(SERIAL_char , &(ptr));
				debug_print("temp_int: %d\n", temp_int);
				uint32_t SERIAL = htonl(temp_int);

				temp_int = strtod(REFRESH_char , &(ptr));
				debug_print("temp_int: %d\n", temp_int);
				uint32_t REFRESH = htonl(temp_int);

				temp_int = strtod(RETRY_char , &(ptr));
				debug_print("temp_int: %d\n", temp_int);
				uint32_t RETRY = htonl(temp_int);

				temp_int = strtod(EXPIRE_char , &(ptr));
				debug_print("temp_int: %d\n", temp_int);
				uint32_t EXPIRE = htonl(temp_int);


				temp_int = strtod(MINIMUM_char , &(ptr));
				debug_print("temp_int: %d\n", temp_int);
				uint32_t MINIMUM = htonl(temp_int);

				int rdlen = strlen(MNAME) + 1 + strlen(RNAME) + 1 + (5 * sizeof(SERIAL) ); //all of the above


		                struct dns_rr dns_rr;
				dns_rr.type = htons(answer_type);
                                dns_rr.class = htons(1);
                                dns_rr.ttl = htonl(json_object_get_int(TTL) );
                                dns_rr.rdlength = htons( rdlen );

                                memcpy(R, &dns_rr, sizeof(dns_rr) );
                                R += sizeof(dns_rr) ;

				// append MNAME
				memcpy(R, MNAME , strlen(MNAME) + 1 );
				R += strlen(MNAME) + 1 ;

				//RNAME now  RNAME now  
				memcpy(R, RNAME , strlen(RNAME) + 1 ); 
				R += strlen(RNAME) + 1 ;

				// serial now
				memcpy(R, &SERIAL , sizeof(SERIAL) );
				R += sizeof(SERIAL);  

				// refresh 
				memcpy(R, &REFRESH , sizeof(REFRESH) );	
				R += sizeof(REFRESH);
		
				// RETRY 
				memcpy(R, &RETRY , sizeof(RETRY) );
				R += sizeof(RETRY);

				// EXPIRE
				memcpy(R, &EXPIRE , sizeof(EXPIRE) );
				R += sizeof(EXPIRE); 

				//MINIMUM  
				memcpy(R, &MINIMUM , sizeof(MINIMUM) );
				R += sizeof(MINIMUM); 	
				
                                reply->sendSize += sizeof(dns_rr) + rdlen;

			}
			json_object_put(parsed_json_b);
                }
        }
	json_object_put(parsed_json_a);


//--------------------------------------------------------------------------------------------------------------------------//

	if (debug > 0 ){
		debug_print("Our response contains\n");
		debug_print(" -->  %d Query id.\n", ntohs(header.id) );

		debug_print(" -->  %d qr \n", (reply_header.qr) );
		debug_print(" -->  %d opcode \n", (reply_header.opcode) );
		debug_print(" -->  %d aa \n", (reply_header.aa) );
		debug_print(" -->  %d tc \n", (reply_header.tc) );
		debug_print(" -->  %d rd \n", (reply_header.rd) );
		debug_print(" -->  %d ra \n", (reply_header.ra) );
		//debug_print(" -->  %d zero \n", (reply_header.zero) );
		debug_print(" -->  %d rcode \n", (reply_header.rcode) );

		debug_print(" -->  %d Answers.\n", ntohs(reply_header.ancount) );
		debug_print(" -->  %d qdcount.\n", ntohs(reply_header.qdcount) );
		debug_print(" -->  %d arcount.\n", ntohs(reply_header.arcount) );
		debug_print(" -->  %d nscount.\n", ntohs(reply_header.nscount) );
	}


        if (PROTO == SOCK_STREAM){

		uint16_t tcp = htons(reply->sendSize);
		char newSendy[bufsize] = {0};
		char *bleh = newSendy;
		memcpy(bleh, &tcp, sizeof(tcp)); 
		bleh += sizeof(tcp) ;
		memcpy(bleh, reply->sendThis, reply->sendSize);
		reply->sendSize += sizeof(tcp);

		memcpy(reply->sendThis, newSendy, reply->sendSize);
		return;
	} else {

		if ( reply->sendSize >= 512 ){
			print("Too Big: %lu bytes, sending the tc flag to query %d \n" , reply->sendSize, ntohs(header.id)  );
			memset(reply->sendThis, 0, bufsize); // wipe it clean
			char *R = reply->sendThis;

			struct dns_header tc_header;
			memcpy(&tc_header, tcbuf, sizeof(tc_header) );
			tc_header.qr = 1;
			tc_header.tc = 1;

			memcpy(R, &tc_header, sizeof(tc_header) );
			reply->sendSize =  sizeof(tc_header) ;
			R +=  sizeof(tc_header);
			tcbuf +=  sizeof(tc_header);

			int whatsleft = cut_here - sizeof(tc_header);
			if ( whatsleft > 0){
				memcpy(R, tcbuf, whatsleft);
				reply->sendSize += whatsleft;
			}
		
			return;



		} else {
			return;
		}
        }


}


int get_random(){

        int ret = 0;
        char *rfile = "/dev/urandom";
        int randfd = open(rfile, O_RDONLY);
        read(randfd, &ret, sizeof(ret) );
        close(randfd);

        if (ret > 0){
                return ret;
        } else {
                return abs(ret);
                // abs or this below
                //ret = -ret;
                //return ret;
        }
}


 
//void do_lookup(char *resolv_this_input, char *dns_server_input, int Query_Type){

 
//char * do_lookup(char *resolv_this_input, char *dns_server_input, int Query_Type, char *hold_here){
void do_lookup(char *resolv_this_input, char *dns_server_input, int Query_Type, char *hold_here){

        int client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if ( client_socket < 0 ){
                perror("client_socket error\n");
                return;
        }

	char *resolv_this = resolv_this_input;
	char *dns_server = dns_server_input;


	char buffer[4096] = {0};
	char *p = buffer;
	
	int scratch = 0;
        struct sockaddr_in my_address, server_address;

        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(PORT);
        server_address.sin_addr.s_addr = inet_addr(dns_server);
        int server_address_len = sizeof(server_address);

	struct dns_header header_thingy;
	struct dns_header *header = &header_thingy;
        header->id = htons( get_random() );
        header->rd = 1;
        header->qdcount = htons(1);
	int header_size = sizeof( struct dns_header );
        memcpy(p, header, header_size);
	//debug_print("header size is %d\n", header_size);


	p += header_size;

	char *alavalathi = calloc(1024 , sizeof(*alavalathi) );
	convert(alavalathi,  resolv_this);

	int qname_size = strlen(alavalathi) + 1;
	memcpy(p, alavalathi, qname_size);
	p[qname_size] = 0;
	
        char readable[bufsize] = {0};
        read_back(p, strlen(alavalathi), readable);
        //debug_print("Question: %s\n", readable);

	free(alavalathi);
	p += qname_size; // <- we moved to the label section

	struct dns_question question;
	int question_size = sizeof(question);
	question.type  = htons(Query_Type);
	question.class = htons(Query_Type);

	//debug_print("Question size: %d\n", question_size );
	memcpy(p, &question, question_size);

	int oursize = question_size + qname_size + header_size;

	char recvbuffer[bufsize] = {0};
	char reply[bufsize] = {0};
	int sendlen = sendto(client_socket, (char *)buffer, oursize , 0, (struct sockaddr *)&server_address, server_address_len);
	int recvlen = recvfrom(client_socket, recvbuffer, bufsize, 0, (struct sockaddr *)&server_address, &server_address_len);

	//debug_print("sendlen: %d\n", sendlen);
	//debug_print("recvd %d\n", recvlen);
	memcpy(reply, &recvbuffer, 4096); 
	char *r = recvbuffer;
	struct dns_header replyHeader;
	memcpy(&replyHeader, r, sizeof(replyHeader) );

	if (debug > 0 ){
		debug_print("The response contains: \n");
		debug_print(" -->  %d Questions.\n", ntohs(replyHeader.qdcount) );
		debug_print(" -->  %d Answers.\n", ntohs(replyHeader.ancount) );
		debug_print(" -->  %d Authoritative Servers.\n", ntohs(replyHeader.nscount) );
		debug_print(" -->  %d Additional Records.\n", ntohs(replyHeader.arcount) );
		debug_print(" -->  %d Query id.\n", ntohs(replyHeader.id) );
	}

	if ( ntohs(replyHeader.ancount) < 0){
		fprintf(stderr, "Error: ancount: %d\n",  ntohs(replyHeader.ancount) );
		_exit(1);
	}


	r += sendlen;

	scratch = find_null(r);

       	r += scratch;

	struct dns_rr rr;
	struct in_addr in;

	memcpy(&rr, r,sizeof(rr) );
	//debug_print(" --> rr_TYPE %d\n", ntohs(rr.type) );
	//debug_print(" --> rr_CLASS %d\n", ntohs(rr.class) );
	//debug_print(" --> rr_TTL %d\n", ntohl(rr.ttl) );
	//debug_print(" --> rr_RDLENGTH %d\n", ntohs(rr.rdlength) );

	r += sizeof(rr) ;
	memcpy(&in.s_addr, r, sizeof(in.s_addr));
	//debug_print("\n --> %s\n", inet_ntoa(in));

	memcpy(hold_here, inet_ntoa(in), 512);
	//debug_print("texty: %s\n", hold_here);
	return;


}


void convert(char *dns, char *host_in){
	int len = strlen(host_in) + 1;
	//debug_print("%s Starting, len: %d\n", __func__ , len);
        //char *host = calloc(1024, sizeof(host) );
	char *host = alloca(len);
	memset(host,0, len);
	//printf("%s Doing memcpy\n", __func__ );
        memcpy(host, host_in, strlen(host_in));
	//printf("%s memcpy completed\n", __func__ );
        strncat(host, ".", strlen(host) );
        int j = 0;
        char *temp = alloca(len);
        char *peg = alloca(len);
	memset(temp,0, len);
	memset(peg,0, len);
        for (int i = 0; i < strlen(host) ; i++){
                //printf("%c\n", host[i]);
                if (host[i] == '.'){
                        //printf("ping %d\n", j);
                        peg[0] = j;
                        strcat(dns, peg);
                        strcat(dns, temp);
                        j = 0;
                        //printf("%s-%s\n", peg, temp);
                        //memset(temp,0,sizeof(temp) );
                        memset(temp,0, len);
                } else {
                        temp[j] = host[i];
                        j++;
                }


        }
	//printf("%s Ending\n", __func__ );

	/*
        for (int i=0; i< strlen(dns); i++){
                printf("dns[%d]: %c int %d\n",i, dns[i], dns[i]) ;
        }
	*/
	
}

void setup_holdmine(){
	char new_ip[bufsize] = {0};
        do_lookup(resolv_this, use_ns,1, new_ip);
	debug_print("dns.google.com is at: %s\n", new_ip);
        if (new_ip[0]){
		flashed = (unsigned long)time(NULL);
                snprintf(holdmine,1024,"%s%s", "dns.google.com:443:", new_ip);
                debug_print("Updating holdmine to %s\n",  holdmine);
		//printf("%s %s[%d]: Ready\n", get_currentTime(), Name, pid);
        } else {
                debug_print("Wierd Error 22.14\n");
        }
}

char * get_currentTime(){
        static char CurrentTime[2048];
        char *y = CurrentTime;
        time_t t;
        time(&t);
        strncpy(CurrentTime, ctime(&t), 1000);
        CurrentTime[strcspn(CurrentTime, "\r\n")] = 0; // works for LF, CR, CRLF, LFCR, ...
        return y;
}


int PopulateList(struct LinkedList *Roller, int slot){

	//setup_holdmine();
		
        for (int i = 0; i <= slot; i++){
                struct Node * cNode = calloc(1, sizeof(*cNode) );
		cNode->TimeStamp = 0;
		cNode->NodeMutex = calloc(1, sizeof(*cNode->NodeMutex) );
		cNode->Count = 0;
		cNode->UsageFlag = 0;
		cNode->TimeDelta = 0;
		cNode->handle = NULL;
		cNode->myslist_text = calloc(1024, sizeof(*cNode->myslist_text) );
		snprintf( cNode->myslist_text, 100, "Blank/New" ); // so we can print legit chars 
		cNode->slist = NULL;
		cNode->Chunky = malloc(sizeof(*cNode->Chunky) );


		Prep_HANDLE(cNode);
		
                if (i == 0 ){
                        // We're on HeadNode
			//puts("We're on HeadNode");
                        Roller->HeadNode = cNode;
                        Roller->TailNode = cNode;
                        Roller->LLSize++;
                        cNode->Next = NULL;
                } else if ( i == 1){
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


void Prep_HANDLE(struct Node * Node){
	// brand new, lets set it up
	Node->handle = curl_easy_init();
	//Node->NodeMutex = malloc(sizeof(Node->NodeMutex) );
	pthread_mutex_init(Node->NodeMutex, NULL);

	Node->Chunky->memory = malloc(1);
	Node->Chunky->size = 0;

        curl_easy_setopt(Node->handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
       	curl_easy_setopt(Node->handle, CURLOPT_WRITEDATA, (void *)Node->Chunky );
        curl_easy_setopt(Node->handle, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(Node->handle,  CURLOPT_USERAGENT, Version); 
#if LIBCURL_VERSION_NUM >= 0x073E00
	if (curl_version_data->version_num >= 0x073E00){
        	curl_easy_setopt(Node->handle,  CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
	} else {
       		//printf("%s %s[%d]: Note: libcurl does not support CURL_HTTP_VERSION_2TLS\n",  get_currentTime(), Name, pid); 

	}
#else
       	//printf("%s %s[%d]: Note: libcurl does not support CURL_HTTP_VERSION_2TLS\n",  get_currentTime(), Name, pid); 
#warning "libcurl version too old to set CURL_HTTP_VERSION_2TLS"
#endif


	int TimeNow = (unsigned long)time(NULL);
	int TimeDelta = TimeNow - flashed;

	if (TimeDelta > ttl_max){
		printf("%s %s INITIAL: Doing lookup, as flashed is stale from %d seconds ago\n",__func__,  get_currentTime(), TimeDelta);
		setup_holdmine();
	} else { 
		//printf("%s %s INITIAL: Deferring lookup, as flashed is recent, %d seconds ago\n", __func__, get_currentTime(), TimeDelta);
		//printf("%s %s INITIAL: We will continue to use _recent_ holdmine: %s\n",  __func__,  get_currentTime(), holdmine);
	}

	if (holdmine[0]){
		//printf("holdmine is %s\n", holdmine);
		struct curl_slist *slist1 = Node->slist;
		slist1 = curl_slist_append(NULL, holdmine);
		curl_easy_setopt(Node->handle, CURLOPT_RESOLVE,slist1);
		//printf("%s %s INITIAL: Setting up handle at %p with slist : %s\n",  __func__,  get_currentTime(), Node->handle, holdmine);
		memcpy( Node->myslist_text, holdmine, strlen(holdmine) ); 
	} else {
		puts("------------ that failed ------------- ");
		//printf("%s %s INITIAL: Wierd Error 22.15, slist too small..\n", __func__,  get_currentTime() );
	}


	Node->TimeStamp = (unsigned long)time(NULL);
}


int WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp){

        //printf("alikullancdcndc---------- \n");
        size_t realsize = size * nmemb;
        struct MemoryStruct *mem = (struct MemoryStruct *)userp;
        char *ptr = realloc(mem->memory, mem->size + realsize + 10);
        if(ptr == NULL) {
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


struct Node * get_CURLHANDLE(){
        // static Node * UseThisNode;

	//pthread_mutex_lock(&mutex);
        if ( UseThisNode == NULL){
                UseThisNode = Roller->HeadNode;
        } else {
                UseThisNode = UseThisNode->Next;
        }
	//pthread_mutex_unlock(&mutex);
        return UseThisNode;

}

 

void findNthWord(char *line_in, int n, char *word){

	// since we decay, copy the incoming to another buffer
	char line[bufsize] = {0};
	memcpy(line, line_in, strlen(line_in) );

        int i = 0;
        char delim[] = " " ;
        char *Field = word;
        char *LinePtr = strtok(line, delim);
        while(LinePtr){
                int _len = strlen(LinePtr) ;
                if (i == n){
                        strncpy(Field, LinePtr, strlen(LinePtr) + 1);
                        break;
                }

                i++;
                LinePtr = strtok(NULL, delim);
        }

        return;
}


int debug_print(char *format, ...){
	if (debug > 0 ){
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

int print(char *format, ...){
	// simple print
	va_list arguments;
	va_start(arguments, format);
	char print_buffer[bufsize];
	snprintf(print_buffer, bufsize, "%s %s[%d]: %s", get_currentTime(), Name, pid, format);
	int done = vfprintf(stdout, print_buffer, arguments);
	va_end(arguments); 
	return done;
}



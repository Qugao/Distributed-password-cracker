
#include <crack.h>

/* Intialize Message passwords
 */
int populatePasswds(Message &msg){
	 std::vector <std::string> passwdList = {"xxo0q4QVK0mOg", // cmps
											"00Pp9Oy0VWmn2", // ucsc
											"zzOzL0bB0ocqo", // lab9
											"yyNhnfhEpDmTY", // CMPS
											"5tQvIqEDV1gzw", // UCSC
											"lqFucz6Kp.jPE"}; // LAB9
	 // std::vector <std::string> passwdList = {"xxo0q4QVK0mOg", 
		// 									 "xxo0q4QVK0mOg", 
		// 									 "xxo0q4QVK0mOg", 
		// 									 "xxo0q4QVK0mOg", 
		// 									 "xxo0q4QVK0mOg", 
		// 									 "xxo0q4QVK0mOg", 
		// 									 "xxo0q4QVK0mOg", 
		// 									 "xxo0q4QVK0mOg"}; 

	int num_passwds = 0;
	for(auto& str: passwdList){											
		for(int i = 0; i < HASH_LENGTH; i++){
			if(i < 13){ 
				msg.passwds[num_passwds][i] = str.at(i);
			}else{
				msg.passwds[num_passwds][i] = '\0';
				break;
			}
		}
		num_passwds++;
	}
	return num_passwds;
}

/* Intialize message data 
 */
void setMsgData(Message &msg){
	std::string cruzid = "oparra";
	char hostname[1024];
	hostname[1023] = '\0';
	gethostname(hostname, 1023);

	for(int i = 0; i < MAX_CRUZID_LEN; i++){
		if( i < 6){
			msg.cruzid[i] = cruzid.at(i);
		}else{
			msg.cruzid[i] = '\0';
			break;
		}
	}
	strcpy(msg.hostname, hostname);
	std::cout << "Server hostname " << msg.hostname << "\n";
	msg.num_passwds = populatePasswds(msg);
	msg.port = htons(get_unicast_port()); 
}

/* Convert msg from host order byte code to 
   network byte order code
 */
void convertHTONL(Message &msg){
	msg.num_passwds = htonl(msg.num_passwds);
}

void convertNTOHL(Message &msg){
	msg.num_passwds = ntohl(msg.num_passwds);
}

/* Sends UDP Message to clients using multicast
 * Declare and intialize UDP socket communication type 
 */
Message Crackserver::sendUDPmsg(){ 
	printf("Started server thread \n");
	// Create socket
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("Could not create socket with SOCK_DGRAM communication type \n");
		exit(-1);
	}

	int ttl = 1;
	if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, (void *) &ttl, sizeof(ttl)) < 0){
		printf("Error setsockopt failed"); 
		exit(-1);
	}
	
	// Create sockaddr_in struct for multicast
	struct sockaddr_in multicastAddr; 
	memset(&multicastAddr, 0, sizeof(multicastAddr));
	multicastAddr.sin_family = AF_INET;
	multicastAddr.sin_addr.s_addr = get_multicast_address();
	multicastAddr.sin_port = htons(get_multicast_port());

	// Create message to be sent
	Message s_msg; 
	setMsgData(s_msg);

	// Encode message
	convertHTONL(s_msg);
 
	// Send message from server to client(s)
	int n = sendto(sockfd, (void*) &s_msg, sizeof(s_msg), 0, 
			(struct sockaddr*) &multicastAddr, sizeof(multicastAddr)); 
	if( n < 0){
		printf("Error, failed to send package \n");
		exit(-1);
	}
	close(sockfd);
	return s_msg;
}

/* Receives TCP Message from client
 * Need to declare and intialize new TCP socket 
 */
void Crackserver::recvTCPmsg(Message &msg){
	// create new socket to recieve TCP packet 
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0){
		printf("Could not create socket with SOCK_STREAM communication type"); 
		exit(-1);
	}

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = msg.port;

    // Bind the socket to the server address
    if (bind(sockfd, (struct sockaddr *)&address, sizeof(address))<0){
        printf("bind failed");
        exit(-1);
    }

    // Set server to listen for a connection
    if (listen(sockfd, 1) < 0){
        printf("server failed to intialize listen");
        exit(-1);
    }

    // Create client address 
   	struct sockaddr_in client_addr;
	socklen_t clilen = sizeof(client_addr);

	// Accept the client socket connection
	int newsockfd = accept(sockfd, 
		(struct sockaddr *) &client_addr, &clilen);
	if(newsockfd < 0){
		printf("client socket connection was not accepted");
		exit(-1); 
	} 

	// Receive cracked password from client
	Message r_msg;
	int n = recv(newsockfd, (void*) &r_msg, sizeof(Message), 0);
	if( n < 0){
		printf("Failed to recieve message from client");
	}

	convertNTOHL(r_msg);
	for(unsigned int i = 0; i < r_msg.num_passwds; i++){
		for(auto &element: r_msg.passwds[i]){
			printf("%c", element);
		}
		printf("\n");
	}
	close(sockfd);
}

void Crackserver::server(){
	Message msg = sendUDPmsg();
	recvTCPmsg(msg);
}

// Create two threads: client and server
// Wait until client thread is joined to join server thread 
int main(){
	// Create server thread
	std::thread* th_serv = new std::thread([](){
		Crackserver* serv = new Crackserver();
		serv->server();
	});
	
	// Wait for client thread to join()
	th_serv->join();

	return 0;
}

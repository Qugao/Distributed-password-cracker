#include <crack.h>
/* Author: Oscar Parra
   Date: 6/3/18
   Email: oparra@ucsc.edu
*/
/* Reference code
   Time elapsed example
   https://stackoverflow.com/questions/2808398/easily-measure-elapsed-time

   Socket programming
   https://www.geeksforgeeks.org/socket-programming-cc/

   Get hostname
   https://stackoverflow.com/questions/504810/how-do-i-find-the-current-machines-full-hostname-in-c-hostname-and-domain-info

   CMPS 109 Course Webcasts
   http://opencast-util.lt.ucsc.edu/search/?seriestitle=CMPS-109-LEC-01-2182-61545

   CMPS 109 Lectures
   https://cmps109-spring18-01.courses.soe.ucsc.edu/lectures
 */

/* Convert msg from network order byte code to 
   host byte order code
 */
void convertHTONL(Message &msg){
	msg.num_passwds = htonl(msg.num_passwds);
}

/* Convert msg from network byte order code to 
   host byte order code
 */
void convertNTOHL(Message &msg){
	msg.num_passwds = ntohl(msg.num_passwds);
}


Message Crackclient::recvUDPmsg(){
	// Create socket 
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0); 
	if (sockfd < 0){
		printf("could not create socket with SOCK_DGRAM communication type \n");
		exit(-1);
	}; 

	// create server struct
	struct sockaddr_in server_addr;
	bzero((char *) &server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(get_multicast_port());

	// bind the socket to the server address
	if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0){
	 	printf("Bind failed");
	 	exit(-1);
	}

	// create mutlticastRequest object
	struct ip_mreq multicastRequest;
	multicastRequest.imr_multiaddr.s_addr = get_multicast_address();
	multicastRequest.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
	 	(void *) &multicastRequest, sizeof(multicastRequest)) < 0){
		printf("Failed to setsockopt");
	 	exit(-1);
	}

	// set socket to receive a single UDP message
	Message r_msg;
	int n = recvfrom(sockfd, (void*) &r_msg, sizeof(Message), 0, NULL, 0);
	if( n < 0){
		printf("Error, failed to receive UDP packet \n");
		exit(-1);
	}
	close(sockfd);
	return r_msg;
}

void Crackclient::crackpasswds(Message &msg){
	// Crack the hashed passwords 
	// hnum keeps track of how many hashed passwds

	std::vector <std::thread*> threads;

	for(unsigned int h_idx = 0; h_idx < msg.num_passwds; h_idx++){ 

		auto f = [&msg, h_idx]{
			char plain[8];

			crack(msg.passwds[h_idx], plain);

			memset(msg.passwds[h_idx], 0, sizeof(msg.passwds[h_idx]));
			strcpy(msg.passwds[h_idx], plain);
			printf("%s \n", msg.passwds[h_idx]);
		};

		// create thread
		std::thread *th = new std::thread{f}; 
		threads.push_back(th);
	}

	for(std::thread* th: threads){
		th->join();
	}


	// for(int h_idx = begin; h_idx < end; h_idx++){ 
	// 	char plain[8];
	// 	char passwd[14];
	// 	strcpy(passwd, msg.passwds[h_idx]);

	// 	crack((const char *) passwd, plain);

	// 	memset(&msg.passwds[h_idx], 0, sizeof(msg.passwds[h_idx]));
	// 	strcpy(msg.passwds[h_idx], plain);
	// }
}

void Crackclient::sendTCPmsg(Message &msg){
	// create new socket to send TCP packet to server
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0){
		printf("Could not create socket with SOCK_STREAM communication type"); 
		exit(-1);
	}

    struct hostent *server = gethostbyname(msg.hostname);
	if(server == NULL) exit(-1);

    struct sockaddr_in serv_addr;
	bzero((char*) &serv_addr, sizeof(serv_addr)); 
	serv_addr.sin_family = AF_INET; 
	bcopy((char *)server->h_addr, (char *) &serv_addr.sin_addr.s_addr, server->h_length);
	
	serv_addr.sin_port = msg.port;

    // connect socket to server
	if(connect(sockfd, (struct sockaddr* ) &serv_addr, sizeof(serv_addr)) < 0){
		printf("Connect failed \n");
		exit(-1);
	} 
	
	// send packet to server with decoded passwds
	int n = write(sockfd, (void*) &msg, sizeof(Message));
	if(n < 0){
		printf("Could not write the message to server");
		exit(-1);
	}

	close(sockfd);
}

/* CrackClient
 * Will recieve UDP Packets from Server with a hashed password
 * Will decrypt the hashed password and pass it back to server
 */
void Crackclient::client(){
	// Begin timer
	std::clock_t begin = clock();

	Message r_msg = recvUDPmsg();
	// decode message
	convertNTOHL(r_msg);

	crackpasswds(r_msg);

	// send other TCP messages
	convertHTONL(r_msg);
	// encode message 
	sendTCPmsg(r_msg);

	// Capture time elapsed
	clock_t end = clock();
	double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
	printf("Elapsed time: %f \n", elapsed_secs );
}

// Create two threads: client and server
// Wait until client thread is joined to join server thread 
int main(){
	// Create client thread
	std::thread* th_cli = new std::thread([](){
		Crackclient* cli = new Crackclient();
		cli->client();
	});
	
	// Wait until client thread is finished then join()
	th_cli->join(); 

	return 0;
}

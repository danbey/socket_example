/* A simple server in the internet domain using TCP
 *    The port number is passed as an argument */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include <rdma/rdma_cma.h>
#include <rdma/rsocket.h>

#include <infiniband/ib.h>


#ifndef USE_RS
#define USE_RS 0
#endif

extern char *optarg;
extern int optind, optopt;
static int use_rs = USE_RS;

#define rs_socket(f,t,p)  use_rs ? rsocket(f,t,p)  : socket(f,t,p)
#define rs_bind(s,a,l)    use_rs ? rbind(s,a,l)    : bind(s,a,l)
#define rs_listen(s,b)    use_rs ? rlisten(s,b)    : listen(s,b)
#define rs_connect(s,a,l) use_rs ? rconnect(s,a,l) : connect(s,a,l)
#define rs_accept(s,a,l)  use_rs ? raccept(s,a,l)  : accept(s,a,l)
#define rs_shutdown(s,h)  use_rs ? rshutdown(s,h)  : shutdown(s,h)
#define rs_close(s)       use_rs ? rclose(s)       : close(s)
#define rs_recv(s,b,l,f)  use_rs ? rrecv(s,b,l,f)  : recv(s,b,l,f)
#define rs_send(s,b,l,f)  use_rs ? rsend(s,b,l,f)  : send(s,b,l,f)
#define rs_recvfrom(s,b,l,f,a,al) \
	        use_rs ? rrecvfrom(s,b,l,f,a,al) : recvfrom(s,b,l,f,a,al)
#define rs_sendto(s,b,l,f,a,al) \
	        use_rs ? rsendto(s,b,l,f,a,al)   : sendto(s,b,l,f,a,al)
#define rs_poll(f,n,t)    use_rs ? rpoll(f,n,t)    : poll(f,n,t)
#define rs_fcntl(s,c,p)   use_rs ? rfcntl(s,c,p)   : fcntl(s,c,p)
#define rs_setsockopt(s,l,n,v,ol) \
	        use_rs ? rsetsockopt(s,l,n,v,ol) : setsockopt(s,l,n,v,ol)
#define rs_getsockopt(s,l,n,v,ol) \
	        use_rs ? rgetsockopt(s,l,n,v,ol) : getsockopt(s,l,n,v,ol)

void error(const char *msg)
{
	perror(msg);
	exit(1);
}

void run_client(const char *addr, int portno)
{
	struct hostent *server;
	int sockfd, n, rt;
	struct sockaddr_in serv_addr;
	char buffer[256], out[256];
	struct pollfd fds[1];

	server = gethostbyname(addr);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}

	sockfd = rs_socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
		error("ERROR opening socket");

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, 
			(char *)&serv_addr.sin_addr.s_addr,
			server->h_length);
	serv_addr.sin_port = htons(portno);
	rt = rs_connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr));
	if (rt < 0)
		error("ERROR connecting");
	printf("Please enter the message: ");
	bzero(buffer,256);
	fgets(buffer,255,stdin);

	fds[0].fd = sockfd;
	fds[0].events = POLLOUT;
	fds[0].revents = 0;

	while (1) {
		fds[0].revents = 0;
		rt = poll(fds, 1, -1);
		if (rt < 0)
			error("polling error");

		if (fds[0].revents) {
			if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				printf("ERROR: revent  0x%x, POLLERR 0x%x, POLLHUP 0x%x, POLLNVAL 0x%x\n",fds[0].revents, POLLERR, POLLHUP, POLLNVAL);
				break;
			}
			if (fds[0].revents & POLLOUT) {
				n = write(sockfd, buffer, strlen(buffer));
				if (n < 0)
					error("ERROR writing to socket");
				fds[0].events = POLLIN;
			}

			if (fds[0].revents & POLLIN) {
				out[0] = '\0';
				n = read(sockfd, out, 255);
				if (n < 0)
					error("ERROR reading from socket");
				printf("%s\n",out);
				fds[0].events = POLLOUT;
			}
		}
	}
	close(sockfd);
}

void run_server(const char *addr, int portno)
{
	int sockfd, newsockfd;
	socklen_t clilen;
	char buffer[256];
	struct sockaddr_in serv_addr, cli_addr;
	int i, n, rt;

	sockfd = rs_socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
		error("ERROR opening socket");

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
	rt = rs_bind(sockfd, (struct sockaddr *) &serv_addr,
				sizeof(serv_addr));
	if (rt < 0)
		error("ERROR on binding");
	rs_listen(sockfd,5);
	clilen = sizeof(cli_addr);
	while (1) {
		newsockfd = rs_accept(sockfd,
				(struct sockaddr *) &cli_addr, 
				&clilen);
		if (newsockfd < 0) 
			error("ERROR on accept");
		for (i = 0; i < 10; i++) {
			bzero(buffer,256);
			n = read(newsockfd,buffer,255);
			if (n < 0) error("ERROR reading from socket");
			printf("Here is the message: %s\n",buffer);
			n = write(newsockfd,"I got your message",18);
			if (n < 0) error("ERROR writing to socket");
		}
		close(newsockfd);
	}
	close(sockfd);
}

void print_usage(const char *appname)
{
	printf("usage: %s\n", appname);
	printf("\t[-s server_address]\n");
	printf("\t[-b bind_address]\n");
	printf("\t[-f address_format]\n");
	printf("\t    name, ip, ipv6, or gid\n");
}

int main(int argc, char *argv[])
{
	int is_server, portno;
	struct hostent *server;
	char *addr, *port = "4555";
	int op, ret;
	int use_rgai;
	struct rdma_addrinfo rai_hints;
	struct addrinfo ai_hints;


	while ((op = getopt(argc, argv, "s:b:f:p:")) != -1) {
		switch (op) {
			case 's':
				addr = optarg;
				is_server = 0;
				break;
			case 'b':
				addr = optarg;
				is_server = 1;
				break;
			case 'f':
				if (!strncasecmp("ip", optarg, 2)) {
					ai_hints.ai_flags = AI_NUMERICHOST;
				} else if (!strncasecmp("gid", optarg, 3)) {
					rai_hints.ai_flags = RAI_NUMERICHOST | RAI_FAMILY;
					rai_hints.ai_family = AF_IB;
					use_rgai = 1;
				} else {
					fprintf(stderr, "Warning: unknown address format\n");
				}
				break;
			case 'p':
				port = optarg;
				break;
			default:
				print_usage(argv[0]);
		}
	}

	if (op < 0) {
		print_usage(argv[0]);
		exit(1);
	}

	portno = atoi(port);

	is_server ? run_server(addr, portno): run_client(addr, portno);

	return 0; 
}

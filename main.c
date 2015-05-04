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

#define MSG_SIZE 255
#define MAX_NUM_RSOCKET 1024

#ifndef USE_RS
#define USE_RS 0
#endif

extern char *optarg;
extern int optind, optopt;
static int use_rs = USE_RS;
static struct rdma_addrinfo rai_hints;
static struct addrinfo ai_hints;

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

void run_client(int use_rgai,char *addr, char *port)
{
	int sockfd, n, rt, i;
	struct sockaddr_in serv_addr;
	char buffer[256] = "JOPA" , out[256];
	struct pollfd fds[MAX_NUM_RSOCKET];
	int portno;
	struct rdma_addrinfo *rai = NULL;
	struct  addrinfo *ai;
	int msg_count = 1, sock_count;

	memset(fds, 0, sizeof(fds));
	memset(buffer, 0, sizeof(buffer));
	/*
	   printf("Please enter the message: ");
	   bzero(buffer,256);
	   fgets(buffer,MSG_SIZE,stdin);
	   */

	for (i = 0; i < MAX_NUM_RSOCKET; i++)
		fds[i].fd = -1;

	rt = use_rgai ? rdma_getaddrinfo(addr, port, &rai_hints, &rai) :
		getaddrinfo(addr, port, &ai_hints, &ai);

	if (rt)
		error("getaddrinfo");

	for (i = 0; i < MAX_NUM_RSOCKET; i++) {

		sockfd = rai ? rs_socket(rai->ai_family, SOCK_STREAM, 0):
			rs_socket(ai->ai_family, SOCK_STREAM, 0);

		if (sockfd < 0){
			char msg[512];
			sprintf(msg,"ERROR opening. position %d", i);
			error(msg);
		}

		rt = rai ? rs_connect(sockfd, rai->ai_dst_addr, rai->ai_dst_len):
			rs_connect(sockfd, ai->ai_addr, ai->ai_addrlen);

		if (rt) {
			char msg[512];
			sprintf(msg,"ERROR connecting to server. position %d, socket %d", i, sockfd);
			fprintf(stderr, "%s\n", msg);
			break;
		}

		fds[i].fd = sockfd;
		fds[i].events = POLLOUT;
		fds[i].revents = 0;
	}

	while (1) {
		fds[0].revents = 0;
		rt = rs_poll(fds, MAX_NUM_RSOCKET, -1);
		if (rt < 0)
			error("polling error");

		for (i = 0; i < MAX_NUM_RSOCKET; i++) {

			if (fds[i].fd < 0)
				continue;

			if (fds[i].revents) {
				if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
					printf("ERROR: revent  0x%x, POLLERR 0x%x, POLLHUP 0x%x, POLLNVAL 0x%x"
							"position %d, socket %d\n",
							fds[i].revents, POLLERR, POLLHUP, POLLNVAL, i, fds[i].fd);
					rs_close(fds[i].fd);
					fds[i].fd = -1;
					fds[i].events = 0;
					fds[i].revents = 0;
					continue;
				}
				if (fds[i].revents & POLLOUT) {
					if (msg_count < 10) {
						strcpy(buffer, "JOPA");
						msg_count++;
					} else {
						memset(buffer, 0, sizeof(buffer));
						msg_count = 0;
					}

					n = rs_send(fds[i].fd, buffer, MSG_SIZE, 0);
					if (n < 0) {
						char msg[512];
						sprintf(msg,"ERROR writing to socket. position %d, socket %d", i, fds[i].fd);
						error(msg);
					}
					fds[i].events = POLLIN;
					continue;
				}

				if (fds[i].revents & POLLIN) {
					out[0] = '\0';
					n = rs_recv(fds[i].fd, out, MSG_SIZE, 0);
					if (n < 0) {
						char msg[512];
						sprintf(msg,"ERROR reading to socket. position %d, socket %d", i, fds[i].fd);
						error(msg);
					}
					printf("%s\n",out);
					fds[i].events = POLLOUT;
					continue;
				}
			}
		}
	}
//	rs_close(sockfd);
}

void run_server(int use_rgai, char *addr, char *port)
{
	int sockfd;
	socklen_t clilen;
	char buffer[256], response[256] = "I got your message";
	struct sockaddr_in serv_addr, cli_addr;
	int i, n, rt;
	struct rdma_addrinfo *rai = NULL;
	struct addrinfo *ai;
	struct pollfd fds[MAX_NUM_RSOCKET];
	int nextfd = 1;

	memset(fds, 0, sizeof(fds));

	for (i = 0; i < MAX_NUM_RSOCKET; i++)
		fds[i].fd = -1;

	if (use_rgai) {
		rai_hints.ai_flags |= RAI_PASSIVE;
		rt = rdma_getaddrinfo(addr, port, &rai_hints, &rai);
	} else {
		ai_hints.ai_flags |= AI_PASSIVE;
		rt = getaddrinfo(addr, port, &ai_hints, &ai);
	}
	if (rt)
		error("getaddrinfo");

	sockfd = rai ? rs_socket(rai->ai_family, SOCK_STREAM, 0):
		rs_socket(ai->ai_family, SOCK_STREAM, 0);

	if (sockfd < 0) 
		error("ERROR opening socket");

	rt = rai ? rs_bind(sockfd, rai->ai_src_addr, rai->ai_src_len):
			rs_bind(sockfd, ai->ai_addr, ai->ai_addrlen);
	if (rt < 0)
		error("ERROR on binding");
	rs_listen(sockfd,5);

	fds[0].fd = sockfd;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	while (1) {
		rt = rs_poll(fds, MAX_NUM_RSOCKET, -1);
		if (rt < 0)
			error("polling error");

		if (fds[0].revents) {
			if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				printf("ERROR: revent  0x%x, POLLERR 0x%x, POLLHUP 0x%x, POLLNVAL 0x%x\n",fds[0].revents, POLLERR, POLLHUP, POLLNVAL);
				break;
			}
			if (fds[0].revents) {
				int newsockfd = -1;

				fds[0].revents = 0;
				newsockfd = rs_accept(sockfd,
						(struct sockaddr *) &cli_addr,
						&clilen);
				if (newsockfd < 0)
					error("ERROR on accept");

				if (nextfd > MAX_NUM_RSOCKET) {
					rs_close(newsockfd);
					break;
				}

				printf("Client %d, sock %d\n",nextfd - 1, newsockfd);
				fds[nextfd].fd = newsockfd;
				fds[nextfd].events = POLLIN;
				fds[nextfd].revents = 0;
				nextfd++;
			}

		}

		for (i = 1; i < MAX_NUM_RSOCKET; i++) {
			if (fds[i].fd < 0  || !fds[i].revents)
				continue;

			if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				printf("ERROR: revent  0x%x, POLLERR 0x%x, POLLHUP 0x%x, POLLNVAL 0x%x\n",fds[0].revents, POLLERR, POLLHUP, POLLNVAL);
				fds[i].fd = -1;
				fds[i].events = 0;
				fds[i].revents = 0;
				continue;
			}

			if (fds[i].revents & POLLIN) {
				bzero(buffer,256);
				n = rs_recv(fds[i].fd, buffer, MSG_SIZE, 0);
				if (n < 0) error("ERROR reading from socket");
				//printf("Here is the message: %s\n",buffer);
				if (buffer[0] == '\0') {
					rs_close(fds[i].fd);
					fds[i].fd = -1;
					fds[i].events = 0;
					fds[i].revents = 0;
				} else {
					n = rs_send(fds[i].fd, response, MSG_SIZE, 0);
					if (n < 0) error("ERROR writing to socket");
					fds[i].revents = 0;
				}
				continue;
			}
		}
	}
	rs_close(sockfd);
	if (rai)
		rdma_freeaddrinfo(rai);
}

void print_usage(const char *appname)
{
	printf("usage: %s\n", appname);
	printf("\t[-s server_address]\n");
	printf("\t[-b bind_address]\n");
	printf("\t[-f address_format]\n");
	printf("\t[-p port_number]\n");
	printf("\t    name, ip, ipv6, or gid\n");
}

int main(int argc, char *argv[])
{
	int is_server, portno;
	struct hostent *server;
	char *addr, *port = "4555";
	int op, ret;
	int use_rgai = 0;


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
/*
	if (op < 0) {
		print_usage(argv[0]);
		exit(1);
	}
*/

	is_server ? run_server(use_rgai, addr, port): run_client(use_rgai, addr, port);

	return 0; 
}

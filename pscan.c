#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>  
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>      

int main(int argc, char **argv) {
    int socket_descriptor;
    int port;
    int start;
    int end;
    int sd2connect;
    struct hostent *hostaddr;
    struct sockaddr_in servaddr;

    if (argc < 4) {
        printf("Usage: %s <IP addr> <Start Port> <End Port>\n", argv[0]);
        return EINVAL;
    }

    start = atoi(argv[2]);
    end = atoi(argv[3]);

    for (port = start; port <= end; port++) {
        socket_descriptor = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket_descriptor == -1) {
            perror("socket()");
            return errno;
        }

        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(port);

        hostaddr = gethostbyname(argv[1]);
        if (hostaddr == NULL) {
            fprintf(stderr, "Error: Host not found.\n");
            return errno;
        }
        memcpy(&servaddr.sin_addr, hostaddr->h_addr, hostaddr->h_length);

        sd2connect = connect(socket_descriptor, (struct sockaddr *) &servaddr, sizeof(servaddr));
        if (sd2connect == -1) {
            printf("Port %d is closed\n", port);
        } else {
            printf("Port %d is open\n", port);
        }
        close(socket_descriptor);
    }
    return 0;
}

#include <iostream>
#include "server.h"

#define PORT 389

using namespace std;




int main(int argc, char *argv[]) {
    Server serv;
    serv.create(PORT);
    serv.start();
    /**
    int socket_fd, new_fd, rv;
    struct addrinfo hints, *s_info;
    struct sockaddr_storage in_addr;
    char s[INET6_ADDRSTRLEN];
    socklen_t sin_size;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    getaddrinfo(NULL, "44444", &hints, &s_info);

    socket_fd = socket(s_info->ai_family,
        s_info->ai_socktype,
        s_info->ai_protocol);

    int yes = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    bind(socket_fd, s_info->ai_addr, s_info->ai_addrlen);

    listen(socket_fd, 10);

    while (1) {
        sin_size = sizeof(in_addr);
        new_fd = accept(socket_fd, (struct sockaddr *)&in_addr, &sin_size);
        inet_ntop(in_addr.ss_family, &(((struct sockaddr_in*)&in_addr)->sin_addr), s, sizeof s);
        printf("Connected %s\n", s);
    }
    
    **/

}
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <thread>


using namespace std;

class Server {
    public:
        int socketfd, newfd, rv;
        struct sockaddr_in serverAddress;
        struct sockaddr_in clientAddress;
        char msg[4096];



        void create(int port);
        void start();

};
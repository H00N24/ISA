#include <iostream>
#include <thread>
#include <vector>
#include <set>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>


using namespace std;

void start_ldap(int newfd, set<vector<string>> data);

class Server {
    public:
        int fd, new_fd, rv;
        struct sockaddr_in adr;
        set<vector<string>> data;

        Server(int port, string file_name);
        void start();

        string trim(string s);

};
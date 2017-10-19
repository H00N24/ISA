#include "server.h"
#include "ldap_fsm.h"


void Server::create(int port) {
    socketfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&serverAddress,0,sizeof(serverAddress));
    serverAddress.sin_family=AF_INET;
	serverAddress.sin_addr.s_addr=htonl(INADDR_ANY);
	serverAddress.sin_port=htons(port);
	bind(socketfd,(struct sockaddr *)&serverAddress, sizeof(serverAddress));
    listen(socketfd, 10);
}

void Server::start() {
    string str;
    char buffer[4096];
    cout << "Server started" << endl;
    while (1) {
        socklen_t sosize  = sizeof(clientAddress);
        newfd = accept(socketfd,(struct sockaddr*)&clientAddress,&sosize);
        str = inet_ntoa(clientAddress.sin_addr);
        cout << str << endl;
        int n = read(newfd, buffer, 4096);
        LDAP_reciever ldap_recv(string(buffer), n);
        
        if (ldap_recv.start())
            cout << "ok" << endl;
        else
            cout << "chyba" << endl;
        break;
    }
}
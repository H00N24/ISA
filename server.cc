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
    cout << "Server started" << endl;
    while (1) {
        socklen_t sosize  = sizeof(clientAddress);
        newfd = accept(socketfd,(struct sockaddr*)&clientAddress,&sosize);
        str = inet_ntoa(clientAddress.sin_addr);
        cout << str << endl;
        LDAP_reciever ldap_recv(newfd);
        
        if (ldap_recv.start() && ldap_recv.message.type == BINDREQUEST) {
            cout << "Bind request ok" << endl;
        } else {
            cout << "\n---chyba--" << endl;            
            cout << ldap_recv.act;
            printf(" %d", ldap_recv.msg[ldap_recv.act]);
        }

        break;
    }
}
/**
 * server.cc
 * LDAP server - ISA 2017/2018
 * Author: Ondrej Kurak
 * Mail: xkurak00@stud.fit.vutbr.cz
 **/

#include "server.h"
#include "ldap_fsm.h"

/** Constructor
 * Server constructor
 * @param port 
 * @param name of db file
*/
Server::Server(int port, string file_name) {
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) {
        cerr << "Socket error" << endl;
        exit(0);
    }

    memset(&adr,0,sizeof(adr));
    adr.sin_family=AF_INET;
	adr.sin_addr.s_addr=htonl(INADDR_ANY);
    adr.sin_port=htons(port);
    
    if (bind(fd,(struct sockaddr *)&adr, sizeof(adr)) == -1) {
        cerr << "Bind error" << endl; 
        exit(0);
    }

    if (listen(fd, 10) == -1) {
        cerr << "Listen error" << endl;
        exit(0);
    }

    ifstream infile(file_name);
    if (!infile.is_open()) {
        cerr << "Data file error" << endl;
        exit(0);
    }

    if(DEBUG) cerr << "CSV loading" << endl;
    string cn, uid, mail;

    while (getline(infile, cn , ';')) {
        vector<string> tmp;
        tmp.push_back(trim(cn));    
        getline(infile, uid , ';');
        tmp.push_back(trim(uid));
        getline(infile, mail);
        tmp.push_back(trim(mail));

        data.emplace(tmp);
    }
}

/** Start of server
 * Starts server and listens for connections,
 * generates new thread for new connection
*/
void Server::start() {
    string str;
    cout << "Server started" << endl;
    while (1) {
        new_fd = accept(fd, NULL, NULL);
        if (new_fd == -1) {
            cerr << "Accept error" << endl;
            continue;
        }
        if(DEBUG) cerr << "New connection" << endl;
        thread t(start_ldap, new_fd, data);
        t.detach();
    }
}

/** Starting LDAP parser
 * Starts LDAP parser
 * @param socket file descriptor
 * @param data from input file
 **/
void start_ldap(int new_fd, set<vector<string>> data) {
    LDAP_parser ldap_recv(new_fd, data);
    while (ldap_recv.start());
    close(new_fd);
}

/** Triming of string
 * Trims string
 * @param input
 * @return trimmed string
*/
string Server::trim(string s) {
    const char* t = " \t\n\r\f\v";
    string tmp = s.erase(0, s.find_first_not_of(t));
    tmp = tmp.erase(tmp.find_last_not_of(t) + 1);
    return tmp;
}
/**
 * ldap_fsm.h
 * LDAP server - ISA 2017/2018
 * Author: Ondrej Kurak
 * Mail: xkurak00@stud.fit.vutbr.cz
 **/

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

/** Starting LDAP parser
 * Starts LDAP parser
 * @param socket file descriptor
 * @param data from input file
 **/
void start_ldap(int newfd, set<vector<string>> data);

/** Class for server
 * Simple IPv4 concurent server
*/
class Server {
public:
    /** Constructor
     * Server constructor
     * @param port 
     * @param name of db file
    */
    Server(int port, string file_name);
    
    /** Start of server
     * Starts server and listens for connections,
     * generates new thread for new connection
    */
    void start();

private:
    int fd; /**< Socket file descriptor **/
    int new_fd; /**< New connection file descriptor **/
    struct sockaddr_in adr; /**< Server adress **/
    set<vector<string>> data; /**< Data from db file */

    /** Triming of string
     * Trims string
     * @param input
     * @return trimmed string
    */
    string trim(string s);
};

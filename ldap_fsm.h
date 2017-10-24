#include <iostream>
#include <string.h>
#include <unistd.h>

#define BINDREQUEST 0x60
#define BINDRESPONSE 0x61
#define SEARCHREQEST 0x63
#define SEARCHRESULTENTRY 0x64
#define SEARCHRESULTDONE 0x65
#define UNBINDREQUEST 0x42

using namespace std;

class LDAP_message {
public:
    int id, l0, l1, l2, l3;
    int type, version;

};

class LDAP_reciever {
public:
    int len; // celkova dlzka prijatej spravy
    int act; // actualna pozicia v stringu
    unsigned char msg[4096]; // sprava
    
    LDAP_message message;

    LDAP_reciever(int newfd);
    bool start(); // 0x30, LL, 0x2, 0-4, message_id
    bool bind_start();
    bool search_start();
    bool unbind_start();

};
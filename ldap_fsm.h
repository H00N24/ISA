#include <iostream>
#include <string.h>


#define BINDREQUEST 0x60
#define BINDRESPONSE 0x61
#define SEARCHREQEST 0x63
#define SEARCHRESULTENTRY 0x64
#define SEARCHRESULTDONE 0x65
#define UNBINDREQUEST 0x42

using namespace std;

class LDAP_message {
public:
    int len;
    char type;

};

class LDAP_reciever {
public:
    int len; // celkova dlzka prijatej spravy
    int act; // actualna pozicia v stringu
    string msg; // sprava
    
    int l1_len; // dlzka prvej casti

    LDAP_reciever(string m, int n);
    bool start(); // 0x30, LL

};
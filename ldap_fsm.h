#include <iostream>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <fstream>
#include <map>
#include <regex>
#include <set>

#define DEBUG 1

#define BINDREQUEST 0x60
#define BINDRESPONSE 0x61
#define SEARCHREQEST 0x63
#define SEARCHRESULTENTRY 0x64
#define SEARCHRESULTDONE 0x65
#define UNBINDREQUEST 0x42

#define AND 0xA0
#define OR 0xA1
#define NOT 0xA2
#define SUBSTRING 0xA4
#define EQUALITY 0xA3

using namespace std;

class LDAP_message {
public:
    int id, l0, l1, l2, l3;
    int size_limit;
    int time_limit;
    int type, version;

};

class Filter {
public:
    int type = -1;
    int length;
    vector<Filter> filters;
    string what;
    string value;
    vector<string> result;
};

class LDAP_receiver {
public:
    int len; // celkova dlzka prijatej spravy
    int act; // actualna pozicia v stringu
    int fd;
    unsigned char ch;
    set< vector<string>> data;
    unsigned char msg[4096]; // sprava
    Filter filter;

    
    LDAP_message message;

    LDAP_receiver(int newfd);
    void next();
    void clear();
    bool start(); // 0x30, LL, 0x2, 0-4, message_id

    // bind request
    bool bind_start();

    // search request
    bool search_start();

    bool unbind_start();

private:
    // ber_functions.cc
    int get_ll();
    int get_int();
    string get_string();

    // filters.cc
    Filter get_filter();
    void print_filters(Filter f);
    vector<string> resolve_filters();

};

class LDAP_sender {
public:
    int len, act;
    int l0;
    int type;
    int fd;
    unsigned char msg[4096] = {0x30, 0, 0x2, 0x1, 0x1,};

    LDAP_sender(int newfd);
    bool send(int type);
    bool bind_response();
};
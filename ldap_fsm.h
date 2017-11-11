#include <iostream>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <vector>
#include <fstream>
#include <map>
#include <regex>
#include <set>

#ifdef NDEBUG
    #define DEBUG 1
#else
    #define DEBUG 0
#endif

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
using namespace std::regex_constants;

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
    map<string, int> known = {{"cn", 0}, {"uid", 1}, {"mail", 2}};
    string what;
    int w;
    string value;
};

class LDAP_parser {
public:
    int len; // celkova dlzka prijatej spravy
    int act; // actualna pozicia v stringu
    int fd;
    unsigned char ch;
    set<vector<string>> data;
    set<vector<string>> res_set;
    Filter filter;

    
    LDAP_message message;

    LDAP_parser(int newfd, set<vector<string>> d);
    void next();
    void clear();
    bool start(); // 0x30, LL, 0x2, 0-4, message_id

    bool bind_req();

    // search request
    bool search_req();

    bool unbind_req();

    void bind_response();
    void search_entry();
    void search_res_done();

private:
    // ber_functions.cc
    int get_ll();
    int get_int();
    string get_string();
    string cn(unsigned char ch);
    string make_ll(string str);
    string make_id(int num);

    // filters.cc
    Filter get_filter();
    void print_filters(Filter f);
    set<vector<string>> resolve_filters(Filter f);

};
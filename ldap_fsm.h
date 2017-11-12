/**
 * ldap_fsm.h
 * LDAP server - ISA 2017/2018
 * Author: Ondrej Kurak
 * Mail: xkurak00@stud.fit.vutbr.cz
 **/

#include <string.h>
#include <unistd.h>
#include <math.h>

#include <iostream>
#include <vector>
#include <fstream>
#include <map>
#include <regex>
#include <set>

/**
 * Macro for debuging (make debug) 
 **/
#ifdef NDEBUG
    #define DEBUG 1
#else
    #define DEBUG 0
#endif

/**
 *  ProtokolOp macros
 **/
#define BINDREQUEST 0x60
#define BINDRESPONSE 0x61
#define SEARCHREQEST 0x63
#define SEARCHRESULTENTRY 0x64
#define SEARCHRESULTDONE 0x65
#define UNBINDREQUEST 0x42

/**
 * Filter macros 
 **/
#define AND 0xA0
#define OR 0xA1
#define NOT 0xA2
#define SUBSTRING 0xA4
#define EQUALITY 0xA3

using namespace std;
using namespace std::regex_constants;

/** LDAP Message
 * Class for storing LDAP message
 **/
class LDAP_message {
public:
    int id; /**< Message ID **/
    int length; /**< Length of message**/
    int size_limit; /**< Maximal number of results (0=all) **/
    int time_limit; /**< Maximal time for sending (0=none) **/
    int type; /**< Type of LDAP message**/
    int version; /**< Version of LDAP **/
};

/** LDAP Filter
 * Class for storing LDAP filters in tree like structure
**/
class Filter {
public:
    int type = -1; /**< Filter type **/
    int length; /**< Length of filter (num of char) **/
    vector<Filter> filters; /**< Stored subfilters **/
    /**< Map for names of AttrDesc **/
    map<string, int> known = {{"cn", 0}, {"commonname", 0},
                              {"uid", 1}, {"userid", 1},
                              {"mail", 2}};
    string what; /**< AttrDesc **/
    int w; /**< Index of AttrDesc **/
    string value; /**< AttrValue **/
};

/** LDAP parser
 * Class for parsing and generating LDAP messages
**/
class LDAP_parser {
public:
    /** Constructor
    * Initialization of LDAP_parser.
    * @param newfd file descriptor
    * @param d data with cn, uid, mail
    **/
    LDAP_parser(int newfd, set<vector<string>> d);

    /** Start of parsing
     * Starts parsing common part of LDAP messages
     * @return true if successful
    **/
    bool start();

private:
    int act; /**< Possition in message**/
    int fd; /**< File descriptor **/
    unsigned char ch; /**< Actual byte from message **/
    set<vector<string>> data; /**< Data from input file**/
    set<vector<string>> res_set; /**< Result of application of filters **/
    Filter filter; /**< Stored filters**/
    LDAP_message message; /**< Message informations**/

    /** Next char of message
     * Reads next char from message and inc act
    **/
    void next();

    /** Clear parser
     * Sets ch = 0 and atc = -1
    **/
    void clear();

    /** BindRequest parsing
     * Verification of BindReqest, sends BindResponse
     * @return true if successful
    **/
    bool bind_req();

    /** SearchRequest parsing
     * Verification of SearchRequest and filtes.
     * Resolve filtes and sends SearchResEntry
     * for every result in res_set and SearchResDone.
     * @return true if successful
    **/
    bool search_req();

    /** UnBindRequest parsing
     * Verification of UnBindRequest 
     * @return false ending connection
    **/
    bool unbind_req();

    /** BindResponse generator/sender
     * Generates and sends BindResponse
    **/
    void bind_response();

    /** SearchResEntry generator/sender
     * Generates and sends SearchResEntry for
     * every result in res_set
    **/
    void search_res_entry();

    /** SearchResDone generator/sender
     * Generates and sends SearchResDone
    **/
    void search_res_done();


    /** ber_functions.cc **/

    /** Loads LL 
     * Loads length of message from actual ch
     * @return length of message
    **/
    int get_ll();

    /** Loads message ID
     * Loads int from actual ch
     * @return ID of message
    */
    int get_int();

    /** Loads string
     * Loads string, starts by using make_ll
     * to get length of string, then loads it
     * @return loaded string
    */
    string get_string();

    /** Transformation from char to str
     * Transforms unsigned char to str
     * @param character
     * @return string(1, ch)
    */
    string cn(unsigned char ch);

    /** Generating string with LL
     * Generates string in LL+string form
     * @param string
     * @return LL+string
    */
    string make_ll(string str);

    /** Generating string from ID
     * Generates string from ID
     * @param ID
     * @return string from ID
    */
    string make_id(int num);

    /**< filters.cc **/

    /** Loading of filter
     * Recursive loading filtes to tree like structure
     * @return Tree like structure of filters
    */
    Filter get_filter();

    /** Printing filters
     * Prints all filters
    */
    void print_filters(Filter f);

    /** Resolving filters
     * Recursively resolves all filters in Filter
     * @return entrys for filter
    */
    set<vector<string>> resolve_filters(Filter f);
};

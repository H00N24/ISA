/**
 * ldap_fsm.cc
 * LDAP server - ISA 2017/2018
 * Author: Ondrej Kurak
 * Mail: xkurak00@stud.fit.vutbr.cz
 **/

#include "ldap_fsm.h"

/** Constructor
* Initialization of LDAP_parser.
* @param newfd file descriptor
* @param d data with cn, uid, mail
**/
LDAP_parser::LDAP_parser(int newfd, set<vector<string>> d) {
    fd = newfd;
    data = d;
    clear();
}

/** BindRequest parsing
 * Verification of BindReqest, sends BindResponse
 * @return true if successful
**/
void LDAP_parser::clear() {
    act = -1;
    ch = 0;
}

/** Next char of message
 * Reads next char from message and inc act
**/
void LDAP_parser::next() {
    read(fd, &ch, 1);
    act++;
}

/** Start of parsing
 * Starts parsing common part of LDAP messages
 * @return true if successful
**/
bool LDAP_parser::start() {
    clear();
    next();
    if (ch != 0x30)
        return false;
    if(DEBUG) cerr << "LDAP message start" << endl;
    next();

    message.length = get_ll();
    if(DEBUG) cerr << "Length: " << message.length << endl;

    if (ch != 0x2)
        return false;
    next();
    
    message.id = get_int();

    if (message.id < 0)
        return false;
    if(DEBUG) cerr << "Message id: " << message.id << endl;
    

    message.type = ch;
    switch (message.type) {
        case BINDREQUEST:
            return bind_req();
        case SEARCHREQEST:
            return search_req();
        case UNBINDREQUEST:
            return unbind_req();
        default:
            return false;
    }
}

/** BindRequest parsing
 * Verification of BindReqest, sends BindResponse
 * @return true if successful
**/
bool LDAP_parser::bind_req() {
    if(DEBUG) cerr << "Type: Bind" << endl;
    
    next();
    int ll = get_ll();
    if(DEBUG) cerr << "Bind len: " << ll << endl;

    if (ch != 0x02)
        return false;
    next();
    
    if (ch != 0x01)
        return false;
    next();
    
    if(DEBUG) cerr << "Version: " << (int)ch << endl;
    next();

    if (ch != 0x04)
        return false;
    next();

    string name = get_string();
    if(DEBUG) cerr << "Name: " << name << endl;

    if (ch != 0x80)
        return false;
    next();

    string simple = get_string();
    if(DEBUG) cerr << "Simple: " << simple << endl;    
    
    if (act == message.length + 1) {
        bind_response();
        return true;
    }
    next();

    if (ch == 0xA0 && act == message.length + 1) {
        bind_response();
        return true;      
    }

    return false;
}

/** SearchRequest parsing
 * Verification of SearchRequest and filtes.
 * Resolve filtes and sends SearchResEntry
 * for every result in res_set and SearchResDone.
 * @return true if successful
**/
bool LDAP_parser::search_req() {
    if(DEBUG) cerr << "Message type: search" << endl;    
    next();
    int ll = get_ll();
    if(DEBUG) cerr << "Search len: " << ll << endl;

    if (ch != 0x04)
        return false;
    next();
    
    string base = get_string();
    if(DEBUG) cerr << "BaseObject: " << base << endl;

    if (ch != 0x0A)
        return false;
    next();

    if (ch != 0x01)
        return false;
    next();

    if (ch > 2)
        return false;
    if(DEBUG) cerr << "Scope: " << (int)ch << endl;
    next();

    if (ch != 0x0A)
        return false;
    next();
        
    if (ch != 0x01)
        return false;
    next();

    if (ch > 3)
        return false;
    if(DEBUG) cerr << "DerefAliases: " << (int)ch << endl;
    next();

    if (ch != 0x02)
        return false;
    next();

    message.size_limit = get_int();
    if(DEBUG) cerr << "Size limit: " << message.size_limit << endl;

    if (ch != 0x02)
        return false;
    next();

    message.time_limit = get_int();    
    if(DEBUG) cerr << "Time limit: " << message.time_limit << endl;

    if (ch != 0x01)
        return false;
    next();

    if (ch != 0x01)
        return false;
    next();

    if(DEBUG) cerr << "TypesOnly: " << (int)ch << endl;
    next();

    filter = get_filter();
    if (filter.type == -1) {
        return false;
    }

    if(DEBUG) print_filters(filter);

    res_set = resolve_filters(filter);
    if(DEBUG) {
        for (auto i: res_set) {
            cerr << i[0] << " " << i[1] << " " << i[2] << endl; 
        }
    }
    
    if (act == message.length) {
        search_res_entry();
        search_res_done();
        return true;
    }
    next();

    if (ch == 0xA0 && act == message.length) {
        search_res_entry();
        search_res_done();
        return true;      
    }

    return false;
}

/** UnBindRequest parsing
 * Verification of UnBindRequest 
 * @return false ending connection
**/
bool LDAP_parser::unbind_req() {
    if(DEBUG) cerr << "Message type: unbind" << endl;
    return false;
}

/** BindResponse generator/sender
 * Generates and sends BindResponse
**/
void LDAP_parser::bind_response() {
    string res = {0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};
    res = cn(0x61) + make_ll(res);
    res = cn(0x02) + make_id(message.id) + res;
    res = cn(0x30) + make_ll(res);

    write(fd, res.c_str(), res.length());
}

/** SearchResEntry generator/sender
 * Generates and sends SearchResEntry for
 * every result in res_set
**/
void LDAP_parser::search_res_entry() {
    vector <string> wh = {"cn", "uid", "mail"};
    for (auto i: res_set) {
        string res = "";
        for (int a = 0; a < 3; a++) {
            string value = cn(0x04) + make_ll(i[a]); // 0x04 ll meno
            value = cn(0x31) + make_ll(value);
            string what = cn(0x04) + make_ll(wh[a]);
            res += cn(0x30) + make_ll(what + value);
        }
        res = cn(0x30) + make_ll(res);
        string name = "uid=" + i[1];
        name = cn(0x04) + make_ll(name);

        res = cn(0x64) + make_ll(name + res);
        res = cn(0x02) + make_id(message.id) + res;
        res = cn(0x30) + make_ll(res);

        write(fd, res.c_str(), res.length());
        message.size_limit -= 1;
        if (!message.size_limit)
            break;
    }        
}

/** SearchResDone generator/sender
 * Generates and sends SearchResDone
**/
void LDAP_parser::search_res_done() {
    string res = {0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};
    res = cn(0x65) + make_ll(res);
    res = cn(0x02) + make_id(message.id) + res;
    res = cn(0x30) + make_ll(res);

    write(fd, res.c_str(), res.length());
}

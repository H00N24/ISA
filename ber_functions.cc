#include "ldap_fsm.h"

int LDAP_parser::get_ll() {
    int tmp = ch;
    if (tmp || act != message.l0 + 1)
        next();    
    if (tmp < 0x81) {
        return tmp;        
    }
    
    tmp -= 0x80;
    int num = 0;
    for (int i = 0; i < tmp; i++, next()) {
        num += ch << ((tmp - 1 - i) * 7);
    }
    return num;
}

int LDAP_parser::get_int() {
    int tmp = ch;
    if (tmp < 1 || tmp > 4)
        return -1;
    next();
    
    int id = 0;
    for (int i = 0; i < tmp; i++, next()) {
        id += ch << ((tmp - 1 - i) * 8);
    }
    return id;
}

string LDAP_parser::get_string() {
    int len = get_ll();
    string text = "";

    for (int i = 0; i < len; i++, next()) {
        text += ch;
    }
    return text;
}

string LDAP_parser::make_ll(string str) {
    string result = "";
    unsigned int len = str.length();
    unsigned char num = 0;
    if (len < 0x81) {
        num = len;
        result += num;
    } else {
        int tmp = ceil((int)(log2(len) + 1) / 7.0);
        num = 0x80 + tmp;
        result += num;
        for (int i = 0; i < tmp; i++) {
            unsigned char r = 0;
            r = len >> ((tmp - 1 - i) * 7);
            r &= ~(1UL << 7);
            result += r;
        }
    }

    result += str;
    return result;
}

string LDAP_parser::make_id(int num) {
    string result = "";
    int tmp = ceil((int)(log2(num) + 1) / 7.0);
    unsigned char r = tmp;
    result += r;
    for (int i = 0; i < tmp; i++) {
            r = 0;
            r = num >> ((tmp - 1 - i) * 8);
            result += r;
    }
    return result;
}

string LDAP_parser::cn(unsigned char ch) {
    string tmp(1, ch);
    return tmp;
}
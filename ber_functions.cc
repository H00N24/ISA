/**
 * ber_functions.cc
 * LDAP server - ISA 2017/2018
 * Author: Ondrej Kurak
 * Mail: xkurak00@stud.fit.vutbr.cz
 **/

#include "ldap_fsm.h"

/** Loads LL 
 * Loads length of message from actual ch
 * @return length of message
**/
int LDAP_parser::get_ll() {
    int tmp = ch;
    if (tmp || act != message.length + 1)
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

/** Loads message ID
 * Loads int from actual ch
 * @return ID of message
*/
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

/** Loads string
 * Loads string, starts by using make_ll
 * to get length of string, then loads it
 * @return loaded string
*/
string LDAP_parser::get_string() {
    int len = get_ll();
    string text = "";

    for (int i = 0; i < len; i++, next()) {
        text += ch;
    }
    return text;
}

/** Transformation from char to str
 * Transforms unsigned char to str
 * @param character
 * @return string(1, ch)
*/
string LDAP_parser::cn(unsigned char ch) {
    string tmp(1, ch);
    return tmp;
}

/** Generating string with LL
 * Generates string in LL+string form
 * @param string
 * @return LL+string
*/
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

/** Generating string from ID
 * Generates string from ID
 * @param ID
 * @return string from ID
*/
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

#include "ldap_fsm.h"

int LDAP_receiver::get_ll() {
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

int LDAP_receiver::get_int() {
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

string LDAP_receiver::get_string() {
    int len = get_ll();
    string text = "";

    for (int i = 0; i < len; i++, next()) {
        text += ch;
    }
    return text;
}

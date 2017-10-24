#include "ldap_fsm.h"

LDAP_reciever::LDAP_reciever(int newfd) {
    len = read(newfd, msg, 4095);
    act = 0;

    cout << len << endl;
    cout << "idem do for" << endl;
    for (int i = 0; i < len; i++)
    {
        //char a = *(msg + i);
        printf("%x ", msg[i]);
    }
    cout << endl;
}


bool LDAP_reciever::start() {
    if (msg[act] != 0x30)
        return false;
    act++;

    message.l0 = msg[act];
    act++;

    if (msg[act] != 0x2)
        return false;
    act++;
    
    int tmp = msg[act];
    if (tmp < 1 || tmp > 4)
        return false;
    act++;
    
    message.id = 0;
    for (int i = 0; i < tmp; i++, act++) {
        message.id += msg[act] << ((tmp - 1 - i) * 8);
    }

    cout << "LL: " << message.l0<< endl;
    cout << "Messageid: " << message.id << endl;

    message.type = msg[act];
    act++;
    switch (message.type) {
        case BINDREQUEST:
            return bind_start();
        case SEARCHREQEST:
            return search_start();
        case UNBINDREQUEST:
            return unbind_start();
        default:
            return false;
    }
}

bool LDAP_reciever::bind_start() {
    cout << "Message type: bind" << endl;
    message.l1 = msg[act];
    act++;
    cout << "Bind len: " << message.l1 << endl;

    if (msg[act] != 0x02 && msg[act+1] != 0x01)
        return false;
    
    act += 2;

    message.version = msg[act];
    act++;
    cout << "Version: " << message.version << endl;

    if (msg[act] != 0x04)
        return false;
    act++;

    message.l2 = msg[act];
    act++;
    cout<< "L2: " << message.l2 << endl;
    act += message.l2;

    if (msg[act] != 0x80)
        return false;
    act++;

    message.l3 = msg[act];
    act++;

    if (act == message.l0 + 2)
        return true;

    if (msg[act] == 0xA0 && act == message.l0 + 1)
        return true;

    return false;
}

bool LDAP_reciever::search_start() {
    cout << "Message type: search" << endl;
    return true;
}

bool LDAP_reciever::unbind_start() {
    cout << "Message type: unbind" << endl;
    return true;
}
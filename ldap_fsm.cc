#include "ldap_fsm.h"

LDAP_reciever::LDAP_reciever(string m, int n) {
    len = n;
    act = 0;
    msg = m;

    cout << n << endl;
    cout << "idem do for" << endl;
    for (int i = 0; i < n; i++)
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
    l1_len = msg[act];
    cout << l1_len << endl;
    return true;

}
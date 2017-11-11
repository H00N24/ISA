#include "ldap_fsm.h"

LDAP_receiver::LDAP_receiver(int newfd) {
    fd = newfd;
    ifstream infile("db.csv");
    if (!infile.is_open()) {
        cerr << "Error: Data file" << endl;
        exit(0);
    }

    if(DEBUG) cerr << "CSV loading" << endl;
    string cn, uid, mail;

    while (getline(infile, cn , ';')) {
        vector<string> tmp;
        tmp.push_back(cn);    
        getline(infile, uid , ';');
        tmp.push_back(uid);
        getline(infile, mail);
        tmp.push_back(mail);

        data.emplace(tmp);
    }
    clear();
    /*
    for (auto i: test_data) {
        cout << i[0] << " " << i[1] << " " << i[2] << endl; 
    }
    exit(1);
    */
}

void LDAP_receiver::next() {
    read(fd, &ch, 1);
    act++;
}

void LDAP_receiver::clear() {
    act = -1;
    ch = 0;
}

bool LDAP_receiver::start() {
    // 0x30

    next();
    if (ch != 0x30)
        return false;
    if(DEBUG) cerr << "LDAP message start" << endl;
    next();

    message.l0 = get_ll();
    if(DEBUG) cerr << "Length: " << message.l0 << endl;

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
            return bind_start();
        case SEARCHREQEST:
            return search_start();
        case UNBINDREQUEST:
            return unbind_start();
        default:
            return false;
    }
}

bool LDAP_receiver::bind_start() {
    if(DEBUG) cerr << "Type: Bind" << endl;
    
    next();
    if(DEBUG) cerr << "Bind len: " << get_ll() << endl;

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

    if(DEBUG) cerr << "Name: " << get_string() << endl;

    if (ch != 0x80)
        return false;
    next();

    if(DEBUG) cerr << "Simple: " << get_string() << endl;    
    
    if (act == message.l0 + 1)
        return true;
    next();

    if (ch == 0xA0 && act == message.l0)
        return true;

    return false;
}

bool LDAP_receiver::search_start() {
    if(DEBUG) cerr << "Message type: search" << endl;    
    next();
    if(DEBUG) cerr << "Search len: " << get_ll() << endl;

    if (ch != 0x04)
        return false;
    next();
    
    if(DEBUG) cerr << "BaseObject: " << get_string() << endl;

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
    if(DEBUG) cerr << "Size limit: " << message.id << endl;

    if (ch != 0x02)
        return false;
    next();

    message.time_limit = get_int();    
    if(DEBUG) cerr << "Time limit: " << message.id << endl;

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

    print_filters(filter);
    return true;
}


bool LDAP_receiver::unbind_start() {
    cout << "Message type: unbind" << endl;
    return true;
}

LDAP_sender::LDAP_sender(int newfd) {
    fd = newfd;
    act = 5;
}

bool LDAP_sender::send(int type) {
    switch (type) {
        case BINDRESPONSE:
            return bind_response();
        case SEARCHRESULTENTRY:
            return true;
        case SEARCHRESULTDONE:
            return true;
        default:
            return false;
    }
}

bool LDAP_sender::bind_response() {
    msg[act] = BINDRESPONSE;
    act+=2; // Doplnit velkost 
    msg[act] = 0x0A;
    act++;
    msg[act] = 0x01;
    act++;
    msg[act] = 0;
    act++;
    msg[act] = 0x4;
    act+=2;
    msg[act] =0x4;
    act+=2;
    msg[1] = act - 2;
    msg[6] = act - 7;
    for (int i = 0; i < act; i++)
    {
        printf("%x ", msg[i]);
    }
    cout << endl;

    int tmp = write(fd, msg, act);
    cout << tmp << endl;
    return true;
}
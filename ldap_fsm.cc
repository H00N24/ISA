#include "ldap_fsm.h"

LDAP_receiver::LDAP_receiver(int newfd) {
    fd = newfd;
    act = -1;
    ifstream infile("db.csv");
    if (!infile.is_open()) {
        cerr << "Error: Data file" << endl;
        exit(0);
    }

    cout << "nacitavam subor" << endl;
    string cn, uid, mail;
    while (getline(infile, cn , ';')) {
        cns.push_back(cn);
        getline(infile, uid , ';');
        uids.push_back(uid);
        getline(infile, mail);
        mails.push_back(mail);
    } 
}

void LDAP_receiver::receive(int newfd) {
    memset(msg, 0, sizeof(msg));
    fd = newfd;
    len = read(newfd, msg, 4095);
    act = 0;

    cout << len << endl;
    for (int i = 0; i < len; i++)
    {
        //char a = *(msg + i);
        printf("%x ", msg[i]);
    }
    cout << endl;
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

    message.l0 = ch;
    if(DEBUG) cerr << "Length: " << message.l0 << endl;
    next();

    if (ch != 0x2)
        return false;
    next();
    
    int tmp = ch;
    if (tmp < 1 || tmp > 4)
        return false;
    next();
    
    message.id = 0;
    for (int i = 0; i < tmp; i++, next()) {
        message.id += ch << ((tmp - 1 - i) * 8);
    }
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
    if(DEBUG) cerr << "Bind len: " << (int)ch << endl;
    next();

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

    int t_len = ch;
    string text;
    next();

    for (int i = 0; i < t_len; i++, next()) {
        text += ch;
    }
    if(DEBUG) cerr << "Name (" << t_len << "): " << text << endl;

    if (ch != 0x80)
        return false;
    next();

    t_len = ch;
    if (ch)
        next();

    string simple;
    for (int i = 0; i < t_len; i++, next()) {
        simple += ch;
    }
    if(DEBUG) cerr << "Simple (" << t_len << "): " << simple << endl;

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
    if(DEBUG) cerr << "Search len: " << (int)ch << endl;
    next();

    if (ch != 0x04)
        return false;
    next();
    
    int t_len = ch;
    next();

    string baseobject;
    for (int i = 0; i < t_len; i++, next()) {
        baseobject += ch;
    }
    if(DEBUG) cerr << "BaseObject (" << t_len << "): " << baseobject << endl;

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

    int tmp = ch;
    if (tmp < 1 || tmp > 4)
        return false;
    next();
    
    message.size_limit = 0;
    for (int i = 0; i < tmp; i++, next()) {
        message.size_limit += ch << ((tmp - 1 - i) * 8);
    }
    if(DEBUG) cerr << "Size limit: " << message.id << endl;

    if (ch != 0x02)
        return false;
    next();
    
    tmp = ch;
    if (tmp < 1 || tmp > 4)
        return false;
    next();
    
    message.time_limit = 0;
    for (int i = 0; i < tmp; i++, next()) {
        message.time_limit += ch << ((tmp - 1 - i) * 8);
    }
    if(DEBUG) cerr << "Time limit: " << message.id << endl;

    if (ch != 0x01)
        return false;
    next();

    if (ch != 0x01)
        return false;
    next();

    if(DEBUG) cerr << "TypesOnly: " << (int)ch << endl;
    next();

    switch (ch) {
        case AND:
            return false;
        case OR:
            return false;
        case NOT:
            return false;
        case SUBSTRING:
            return false;
        case EQUALITY:
            return equality_match();
        default:
            return false; 
    }

    return true;
}

bool LDAP_receiver::equality_match() {
    if(DEBUG) cerr << "Filter type: equality" << endl;
    next();
    if(DEBUG) cerr << "Length: " << (int)ch << endl;
    next();

    if (ch != 0x04)
        return false;
    next();

    int t_len = ch;
    next();

    string attdesc;
    for (int i = 0; i < t_len; i++, next()) {
        attdesc += ch;
    }
    if(DEBUG) cerr << "AttributeDesc (" << t_len << "): " << attdesc << endl;

    if (ch != 0x04)
        return false;
    next();

    t_len = ch;
    next();

    string assertval;
    for (int i = 0; i < t_len; i++, next()) {
        assertval += ch;
    }
    if(DEBUG) cerr << "AssertValue (" << t_len << "): " << assertval << endl;

    if (ch != 0x30)
        return false;
    if (filter.type == -1) {
        filter.type = EQUALITY;
        filter.what = attdesc;
        filter.value = assertval;
    } else {
        // TODO
        Filter *p = new Filter;
    }
    return search_end();
}

bool LDAP_receiver::search_end() {
    next();
    int n_len = ch;
    if (!len)
        return true;
    // TODO dorobit koniec 
}


bool LDAP_receiver::aply_filters() {
    return true; //TODO
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
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

    return true;
}

Filter LDAP_receiver::get_filter() {
    Filter f;
    f.type = ch;
    if(DEBUG) cerr << "Filter type: ";
    switch (f.type) {
        case EQUALITY:
            if(DEBUG) cerr << "Equality" << endl;
            break;
        case SUBSTRING:
            if(DEBUG) cerr << "Substring" << endl;
            break;
        case AND:
            if(DEBUG) cerr << "and" << endl;
            break;
        case OR:
            if(DEBUG) cerr << "Or" << endl;
            break;
        case NOT:
            if(DEBUG) cerr << "Neg" << endl;
            break;
        default:
            if(DEBUG) cerr << "Unknown" << endl;
        return f;
    }
    next();
    f.length = get_ll();
    if(DEBUG) cerr << "Length: " << f.length << endl;
    
    if (f.type != EQUALITY && f.type != SUBSTRING) {
        int tmp_len = f.length;
        while (tmp_len) {
            f.filters.push_back(get_filter());
            tmp_len -= 2 + f.filters.back().length;          
        }
    }

    if (f.type == EQUALITY) {   
        if (ch != 0x04) {
            f.type = -1;
            return f;            
        }
        next();

        f.what = get_string();
        if(DEBUG) cerr << "AttributeDesc: " << f.what << endl;

        if (ch != 0x04) {
            f.type = -1;
            return f;            
        }
        next();

        f.value = get_string();
        if(DEBUG) cerr << "AssertValue: " << f.value << endl;
    }

    if (f.type == SUBSTRING) {

    }
    return f;
}

bool LDAP_receiver::equality_match() {
    if(DEBUG) cerr << "Filter type: equality" << endl;
    next();
    if(DEBUG) cerr << "Length: " << get_ll() << endl;

    if (ch != 0x04)
        return false;
    next();

    string attdesc = get_string();
    if(DEBUG) cerr << "AttributeDesc: " << attdesc << endl;

    if (ch != 0x04)
        return false;
    next();

    string assertval = get_string();
    if(DEBUG) cerr << "AssertValue: " << assertval << endl;

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
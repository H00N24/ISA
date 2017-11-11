#include "ldap_fsm.h"


void LDAP_receiver::print_filters(Filter f) {
    switch (f.type) {
        case EQUALITY:
            if(DEBUG) cerr << "Equality ";
            break;
        case SUBSTRING:
            if(DEBUG) cerr << "Substring ";
            break;
        case AND:
            if(DEBUG) cerr << "And ";
            break;
        case OR:
            if(DEBUG) cerr << "Or ";
            break;
        case NOT:
            if(DEBUG) cerr << "Neg ";
            break;
        default:
            if(DEBUG) cerr << "Unknown ";
    }
    cout << f.filters.size() << endl;
        
    for (auto i: f.filters) {
        cout << "-> ";
        print_filters(i);
    }
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
        if (ch != 0x04) {
            f.type = -1;
            return f;            
        }
        next();

        f.what = get_string();
        if(DEBUG) cerr << "AttributeDesc: " << f.what << endl;

        if (ch != 0x30) {
            f.type = -1;
            return f;            
        }
        next();

        int tmp_len = get_ll();
        string tmp_str;
        while(tmp_len) {
            unsigned char val = ch;
            next();

            tmp_str = get_string();
            switch (val) {
                case 0x80:
                    f.value += tmp_str + ".*";
                    break;
                case 0x81:
                    f.value += ".*" + tmp_str + ".*";
                    break;
                case 0x82:
                    f.value += ".*" + tmp_str;
                    break;
                default:
                    f.type = -1;
                    return f;
            }
            
            tmp_len -= 2 + tmp_str.length();
        }
        if(DEBUG) cerr << "AssertValue: " << f.value << endl;        
    }
    return f;
}
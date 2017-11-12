/**
 * filters.cc
 * LDAP server - ISA 2017/2018
 * Author: Ondrej Kurak
 * Mail: xkurak00@stud.fit.vutbr.cz
 **/

#include "ldap_fsm.h"


/** Loading of filter
 * Recursive loading filtes to tree like structure
 * @return Tree like structure of filters
*/
Filter LDAP_parser::get_filter() {
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
        f.w = f.known[f.what];
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
        f.w = f.known[f.what];
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

/** Printing filters
 * Prints all filters
*/
void LDAP_parser::print_filters(Filter f) {
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
    if(DEBUG) cerr << f.filters.size() << endl;
        
    for (auto i: f.filters) {
        if(DEBUG) cerr << "-> ";
        print_filters(i);
    }
}

/** Resolving filters
 * Recursively resolves all filters in Filter
 * @return entrys for filter
*/
set<vector<string>> LDAP_parser::resolve_filters(Filter f) {
    set<vector<string>> result;
    if (f.type == EQUALITY || f.type == SUBSTRING) {
        for (auto i: data) {
            if (regex_match(i[f.w], regex(f.value, ECMAScript | icase))) {
                result.emplace(i);
            }
        }
    }

    if (f.type == NOT) {
        set<vector<string>> tmp = resolve_filters(f.filters[0]);
        for (auto i: data) {
            if (tmp.find(i) == tmp.end()) {
                result.emplace(i);
            }
        }
    }

    if (f.type == OR) {
        for (auto i: f.filters) {
            set<vector<string>> tmp = resolve_filters(i);
            result.insert(tmp.begin(), tmp.end());
        }
    }

    if (f.type == AND) {
        result = resolve_filters(f.filters[0]);
        for (auto i: f.filters) {
            set<vector<string>> tmp = resolve_filters(i);
            set<vector<string>> tmp1 = result;
            result.clear();
            set_intersection(tmp1.begin(), tmp1.end(),
                             tmp.begin(), tmp.end(),
                             inserter(result, result.begin()));            
        }
    }

    return result;
}

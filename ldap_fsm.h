#include <iostream>
#include <vector>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <string.h>
#include <unistd.h>
#include <math.h>


/* Debugovacie makro, make debug */
#ifdef NDEBUG
    #define DEBUG 1
#else
    #define DEBUG 0
#endif

/* ProtokolOp */
#define BINDREQUEST 0x60
#define BINDRESPONSE 0x61
#define SEARCHREQEST 0x63
#define SEARCHRESULTENTRY 0x64
#define SEARCHRESULTDONE 0x65
#define UNBINDREQUEST 0x42

/* Filter */
#define AND 0xA0
#define OR 0xA1
#define NOT 0xA2
#define SUBSTRING 0xA4
#define EQUALITY 0xA3

using namespace std;
using namespace std::regex_constants;

/* Trieda pre ukladanie udajov o LDAP sprave */
class LDAP_message {
public:
    int id; /* ID spravy */
    int length; /* Dlzka spravy */
    int size_limit; /* Maximalny pocet vratenych vysledkov */
    int time_limit; /* Max cas pre spracovanie, neimplementovane */
    int type; /* Typ LDAP spravy*/
    int version; /* Verzia LDAP */
};

/* Trieda pre ukladanie stromov struktury LDAP filtrov */
class Filter {
public:
    int type = -1; /* Typ filtra */
    int length; /* Dlzka obsahu filtra */
    vector<Filter> filters; /* Zoznam podfilrov */
    /* Mapa pre cislovanie poloziek csv suboru */
    map<string, int> known = {{"cn", 0}, {"CommonName", 0},
                              {"uid", 1}, {"UserID", 1},
                              {"mail", 2}};
    string what; /* Nazov stlpca */
    int w; /* index stlpca */
    string value; /* Hodnota na vyhladavanie */
};

/* Trieda pre spracovavanie a odosielanie LDAP sprav */
class LDAP_parser {
public:
    /* Konstruktor
    Vytvori a inicializuje triedu

    Parametre:
        int newfd - file descriptor z ktoreho ma citat/posielat
        set<vector<string>> d - data nad ktorymi operuje
    */
    LDAP_parser(int newfd, set<vector<string>> d);

    /* Prejdenie spolocnim zaciatkom LDAP sprav
    Prejde cez zaciatok, ktory zdielaju vsetky LDAP spravy.
    nasledne zavola spravu podla ProtocolOp.
    */
    bool start();

private:
    int act; /* aktualna pozicia v sprave */
    int fd; /* file descriptor socketu*/
    unsigned char ch; /* aktualne spracovavany byte */
    set<vector<string>> data; /* data z vstupneho suboru */
    set<vector<string>> res_set; /* vysledok po aplikovani filtrov */
    Filter filter; /* Filtre v stromovej strukture */
    LDAP_message message; /* Udaje o aktualne sprave */

    /* Citanie dalsieho znaku
    Precita nasledujuci znak do ch, zvacsi act.
    */
    void next();

    /* Vycistenie LDAP_parser
    Vycisti ch a nastavi act na -1.
    */
    void clear();

    /* Spracovanie BindRequest
    Spracuje BindRequest, pokial je to sprava typu BindRequest,
    odosle prislusny BindResponse.

    Navratova hodnota:
        bool - true pokial sprava splna BindRequest, false inak.
    */
    bool bind_req();

    /* Spracovanie SearchRequest
    Spracuje SearchRequest, precita a ulozi filre do filter.
    Ak vsetko prebehlo v poriadku vyfiltruje vysledky, pre kazdy zaznam
    posle SearchEntry a nasledne SearchResDone

    Navratova hodnota:
        bool - true ak sprava je SearchRequest, false inak
    */
    bool search_req();

    /* Spracovanie UnBindRequest
    Spracovanie UnBindRequest

    Navratova hodnota:
        bool - false ak je to sprava UnBindRequest
    */
    bool unbind_req();

    /* Spracovanie BindResponse
    Vytvorenie a odoslanie BindResponse
    */
    void bind_response();

    /* Spracovanie SearchResEntry
    Vytvore a odoslanie SearchResEntry pre kazdy vysledok v res_set
    */
    void search_entry();

    /* Spracovanie SearchResDone
    Vytvorenie a odoslanie SearchResDone
    */
    void search_res_done();


    /* ber_functions.cc */

    /* Ziskanie LL
    Zoberie aktualne ch, podla jeho hodnoty korektne nacita
    hodnotu dlzky

    Navratova hodnota:
        int - dlzka nasledujucej casti spravy/retazca
    */
    int get_ll();

    /* Ziskanie ID
    Zoberie aktualne ch, podla jeho velkosti zoberie
    nasledujuce byty a vytvori z nich ID

    Navratova hodnota:
        int - ID spravy
    */
    int get_int();

    /* Ziskanie retazca
    Podla aktualneho ch, za pomoci get_ll() nacita retazec

    Navratova hodnota:
        string - nacitany retazec
    */
    string get_string();

    /* Premena unsigned char na retazec
    Zoberie unsigned char a vrati retazec o velkosti 1

    Navratova hodnota:
        string - hodnota ch o velkosti 1
    */
    string cn(unsigned char ch);

    /* Vytvorenie retazca s dlzkou v tvare ll
    Podla zadaneho retazca mu vytvori predponu s velkostou v tvare ll

    Parametre:
        string str - vstpny retazec
    Navratova hodnota:
        string - retazec s predponou LL

    */
    string make_ll(string str);
    string make_id(int num);

    /* filters.cc */
    Filter get_filter();
    void print_filters(Filter f);
    set<vector<string>> resolve_filters(Filter f);

};
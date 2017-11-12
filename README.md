# ISA - LDAP server
Implementacia jednoducheho, paralelneho LDAP serveru.
Server podporuje LDAPv2 (simple bind).
Server podporuje spravy BindRequest, SearchRequest, UnBindRequest. Ine spravy su ingnorovane, a spojenie je ukoncene.
Server odpoveda spravamy BindResponse, SearchResEntry, SearchResDone.
Pre server nie je potrebne aby komunikacia zacala spravou BindRequest.
Viac informaci: manual.pdf, RFC: 2251, 2252, 2254, 4511.

### Podporovane filtre
* And
* Or
* Not
* EqualityMatch
* Substring

### Rozsirenia
* utf-8 - narodne znaky 

### Pouzitie
 ```
 ./myldap {-p <port>} -f file
 ```
 * -p \<port\> - port pre server, bez zadanie je 389
 * -f file - subor s databazou 

## Obsah archivu
### Zdrojove súbory
* myldap.cc - spustanie servera
* server.cc - paralelny server
* ldap_fsm.cc - stavovy automat na spracovanie LDAP sprav
* filters.cc - spracovanie LDAP filtrov
* ber_functions.cc - spracovie BER

### Hlavickove subory
* ldap_fsm.h - pre ldap_fsm.cc, filters.cc, ber_functions.cc
* server.h - pre server.cc

### Dokumentacne subory
* manual.pdf - podrobna dokumentacia
* README - readme subor

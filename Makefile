SRC= myldap.cc server.cc ldap_fsm.h ldap_fsm.cc filters.cc ber_functions.cc
HEAD= ldap_fsm.h server.h

default: myldap

myldap: $(HEAD) $(SRC)
	g++ $(HEAD) $(SRC) -std=c++11 -o myldap

clean:
	rm myldap
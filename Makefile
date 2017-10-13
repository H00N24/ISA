default: myldap

myldap: myldap.cc
	g++ myldap.cc -std=c++11 -o myldap

clear:
	rm myldap
SRC= *.cc
HEAD= *.h
CXX= g++
FLAGS= -std=c++11 -pthread


#-DNDEBUG

default: myldap

myldap: $(HEAD) $(SRC)
	$(CXX) $(FLAGS) $^ -o myldap

debug: $(HEAD) $(SRC)
	$(CXX) $(FLAGS) -DNDEBUG $^ -o myldap

tar:
	tar -cf xkurak00.tar manual.pdf $(SRC) $(HEAD) Makefile
clean:
	rm myldap
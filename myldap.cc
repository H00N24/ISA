#include <iostream>
#include "server.h"

#define PORT 389

using namespace std;

int main(int argc, char *argv[]) {
    
    Server serv(PORT, "db.csv");
    serv.start();
}
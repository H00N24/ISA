#include "server.h"


using namespace std;

int main(int argc, char *argv[]) {
    int opt = 0;
    string file_name = "";
    int port = 389;
    while ((opt = getopt(argc, argv, "p:f:")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'f':
                file_name = optarg;
                break;
            default:
                cerr << "Arg error" << endl;
                exit(0);
        }
    }

    Server serv(port, file_name);
    serv.start();
}
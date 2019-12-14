#include "cmu_tcp.h"

/*
 * Param: sock - used for reading and writing to a connection
 *
 * Purpose: To provide some simple test cases and demonstrate how 
 *  the sockets will be used.
 *
 */
void functionality(cmu_socket_t  * sock){
    char buf[9898];
    // FILE *file_for_write;
    FILE *file_for_read;
    // int n;
    // n = 1;
    int read = 1;
    int total = 0;
    file_for_read = fopen("./test/random.input","rb");
    puts("123");
    fseek(file_for_read,0,SEEK_END);
    long len = ftell(file_for_read);
    fseek(file_for_read,0,SEEK_SET);
    cmu_write(sock,(char*) &len,8);
    while(read > 0 ){
        read = fread(buf, 1, 2000, file_for_read);
        total = total + read;
        printf("read from file  is %d total = %d len = %d\n", read, total, (int)len);
        if(read > 0)
            cmu_write(sock, buf, read);
    }
    printf("read total = %d\n", total);
    // close((int)file_for_read);
    // total = 0;
    // int len2;
    // cmu_read(sock,&len2,4,NO_FLAG);
    // file_for_write = fopen("./test/f2.txt", "w+");
    // while(total  < len2 && n != 0){
    //     n = cmu_read(sock, buf, 2000, NO_FLAG);
    //     total = total + n;
    //     //printf("n = %d,total = %d\n", n,total);
    //     fwrite(buf, 1, n, file_for_write);
    // }
    // printf("get total = %d\n", total);
    // close(file_for_write);
}

/*
 * Param: argc - count of command line arguments provided
 * Param: argv - values of command line arguments provided
 *
 * Purpose: To provide a sample initator for the TCP connection to a
 *  listener.
 *
 */
int main(int argc, char **argv) {
	int portno;
    char *serverip;
    char *serverport;
    cmu_socket_t socket;
    
    serverip = getenv("server15441");
    if (serverip) ;
    else {
        serverip = "10.0.0.1";
    }

    serverport = getenv("serverport15441");
    if (serverport) ;
    else {
        serverport = "15441";
    }
    portno = (unsigned short)atoi(serverport);


    if(cmu_socket(&socket, TCP_INITATOR, portno, serverip) < 0)
        exit(EXIT_FAILURE);
    printf("[DEBUG] tcp socket handshakes done");
    
    functionality(&socket);

    if(cmu_close(&socket) < 0)
        exit(EXIT_FAILURE);
    return EXIT_SUCCESS;
}

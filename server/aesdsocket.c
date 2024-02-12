#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <sys/types.h> 
#include <sys/stat.h>
#include <errno.h>


#define PORT 9000
#define DATA_FILE "/var/tmp/aesdsocketdata"
#define BUFFER_SIZE 1024

int sockfd;

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        syslog(LOG_INFO, "Caught signal, exiting");
        close(sockfd);
        remove(DATA_FILE);
        closelog();
        exit(EXIT_SUCCESS);
    }
}

void handle_client(int client_socket) {
    FILE *file = fopen(DATA_FILE, "a+");
    if (file == NULL) {
        syslog(LOG_ERR, "Error opening data file: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    while ((bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0)) > 0) {
        if (fwrite(buffer, 1, (size_t)bytes_received, file) != (size_t)bytes_received) {
            syslog(LOG_ERR, "Error writing to data file: %s", strerror(errno));
            fclose(file);
            exit(EXIT_FAILURE);
        }

        if (memchr(buffer, '\n', bytes_received) != NULL) {
            fflush(file); 
            fseek(file, 0, SEEK_SET); 
           
            ssize_t bytes_sent;
            while ((bytes_sent = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
                if (send(client_socket, buffer, bytes_sent, 0) != bytes_sent) {
                    syslog(LOG_ERR, "Error sending data to client: %s", strerror(errno));
                    fclose(file);
                    exit(EXIT_FAILURE);
                }
            }
            // Check for read error
            if (ferror(file)) {
                syslog(LOG_ERR, "Error reading from data file: %s", strerror(errno));
                fclose(file);
                exit(EXIT_FAILURE);
            }
        }
    }

    // Check for receive error
    if (bytes_received < 0) {
        syslog(LOG_ERR, "Error receiving data from client: %s", strerror(errno));
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fclose(file);
    close(client_socket);
}




int main(int argc, char *argv[]) {
    struct sockaddr_in serv_addr, client_addr;
    int client_socket;
    socklen_t client_addr_len = sizeof(client_addr);

    // Signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Open syslog
    openlog("aesdsocket", LOG_PID, LOG_USER);

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        syslog(LOG_ERR, "Error opening socket");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Bind socket to port
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        syslog(LOG_ERR, "Error binding socket");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(sockfd, 5) < 0) {
        syslog(LOG_ERR, "Error listening on socket");
        exit(EXIT_FAILURE);
    }

    // Daemon mode
    if (argc > 1 && strcmp(argv[1], "-d") == 0) {
        pid_t pid = fork();
        if (pid < 0) {
            syslog(LOG_ERR, "Error forking process");
            exit(EXIT_FAILURE);
        }
        if (pid > 0) {
            exit(EXIT_SUCCESS); // Parent exits
        }
        umask(0); // Unmask the file mode
        setsid(); // Create a new session
    }

    // Main loop to accept connections
    while (1) {
        client_socket = accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            syslog(LOG_ERR, "Error accepting connection");
            exit(EXIT_FAILURE);
        }
        handle_client(client_socket);
        
        // Log message to syslog
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        syslog(LOG_INFO, "Closed connection from %s", client_ip);
    }

    return 0;
}

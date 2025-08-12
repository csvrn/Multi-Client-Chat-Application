#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h> 
#include <pthread.h>
#include <time.h>

struct sockaddr_in *createIPv4Address(char *ip, int port);
void listenOnThread(int socketFD);
void listenMessages(int socketFD);

bool serverDisconnected = false;
bool incorrectPassword = false;
pthread_mutex_t disconnectMutex = PTHREAD_MUTEX_INITIALIZER;

struct sockaddr_in *createIPv4Address(char *ip, int port)
{
    struct sockaddr_in *address = malloc(sizeof(struct sockaddr_in));
    address->sin_port = htons(port);
    address->sin_family = AF_INET;

    if (strlen(ip) == 0)
    {
        address->sin_addr.s_addr = INADDR_ANY;
    }
    else
    {
        inet_pton(AF_INET, ip, &address->sin_addr.s_addr);
    }
    return address;
}

int main()
{
    printf("Welcome!\n");

    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in *address = createIPv4Address("127.0.0.1", 2000);

    int result = connect(socketFD, (const struct sockaddr *)address, sizeof(*address));
    if (result == 0)
    {
        // printf("Connection was successful!\n");
    }
    else
    {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    char *name = NULL;
    size_t nameSize = 0;
    printf("Please enter your name:\n");
    ssize_t nameCount = getline(&name, &nameSize, stdin);
    name[nameCount - 1] = 0; 

    char *password = NULL;
    size_t passwordSize = 0;
    printf("Enter password:\n");
    ssize_t passwordCount = getline(&password, &passwordSize, stdin);
    password[passwordCount - 1] = 0;

    char buffer[1024];
    sprintf(buffer, "%s:%s", name, password);
    send(socketFD, buffer, strlen(buffer), 0);
   
    ssize_t amountReceived = recv(socketFD, buffer, sizeof(buffer) - 1, 0); 
    buffer[amountReceived] = '\0';                                          
    printf("%s \n", buffer);

    if (strcmp(buffer, "Incorrect password") == 0 || amountReceived == 0)
    {
        printf("Incorrect password, disconnecting...\n");
        pthread_mutex_lock(&disconnectMutex);
        incorrectPassword = true;
        serverDisconnected = true; 
        pthread_mutex_unlock(&disconnectMutex);
        close(socketFD); 
        free(name);
        free(password);
        free(address);
        return 0; 
    }
   
    listenOnThread(socketFD);

    char *line = NULL;
    size_t lineSize = 0;

    if (!incorrectPassword)
    {
        usleep(200000);
        printf("Type a message to send to the group chat \nType a message starting with @username/ to send a private message\n(or type 'exit' to disconnect): \n");
    }
    while (true)
    {
        pthread_mutex_lock(&disconnectMutex);
        if (serverDisconnected || incorrectPassword)
        {
            pthread_mutex_unlock(&disconnectMutex);
            break;
        }
        pthread_mutex_unlock(&disconnectMutex);

        ssize_t charCount = getline(&line, &lineSize, stdin);
        line[charCount - 1] = 0; 

        if (charCount > 0)
        {
            if (strcmp(line, "exit") == 0)
            {
                printf("Exiting from the application...\n");
                sprintf(buffer, "%s has disconnected", name);
                send(socketFD, buffer, strlen(buffer), 0);
                break; 
            }

            time_t rawTime;
            struct tm *timeInfo;
            char timeBuffer[20];

            time(&rawTime);
            timeInfo = localtime(&rawTime);
            strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M", timeInfo);

            // for the timestamp on the same line as user input
            printf("You: %s (%s)\n", line, timeBuffer);

            // preparing message as username:message
            sprintf(buffer, "%s (%s)", line, timeBuffer);
            ssize_t amountWasSent = send(socketFD, buffer, strlen(buffer), 0);
            if (amountWasSent < 0)
            {
                perror("send");
                break;
            }
        }

        pthread_mutex_lock(&disconnectMutex);
        if (serverDisconnected)
        {
            pthread_mutex_unlock(&disconnectMutex);
            break;
        }
        pthread_mutex_unlock(&disconnectMutex);
    }

    free(line);
    free(name);
    free(password);
    close(socketFD);
    free(address);

    return 0;
}

void listenOnThread(int socketFD)
{
    pthread_t id;
    pthread_create(&id, NULL, (void *(*)(void *))listenMessages, (void *)(intptr_t)socketFD);
}

void listenMessages(int socketFD)
{
    char buffer[1024];
    while (true)
    {
        memset(buffer, 0, sizeof(buffer));                                    
        ssize_t amountReceived = recv(socketFD, buffer, sizeof(buffer) - 1, 0); 
        if (amountReceived > 0)
        {
            buffer[amountReceived] = '\0'; 

            char *message = strtok(buffer, "\n");
            while (message != NULL)
            {
                if (strcmp(message, "Authentication successful") != 0)
                {
                    printf("%s \n", message);
                }
                message = strtok(NULL, "\n");
            }
        }
        else if (amountReceived == 0)
        {
            printf("Server disconnected.\n");

            pthread_mutex_lock(&disconnectMutex);
            serverDisconnected = true;
            pthread_mutex_unlock(&disconnectMutex);

            exit(EXIT_SUCCESS);
        }
        else
        {
            perror("recv");
            break;
        }
    }
    close(socketFD);
}


#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h> 
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <errno.h>

#define SALT_SIZE 16
#define HASH_SIZE 32

//declarations

struct AcceptedSocket
{
    int acceptedSocketFD;
    struct sockaddr_in address;
    char username[128];
    bool acceptedSuccessfully;
    int error;
};
struct AcceptedSocket acceptedSockets[10];
int acceptedSocketsCount = 0;

struct sockaddr_in *createIPv4Address(char *ip, int port);
void removeSocket(int socketFD, bool unAuthenticated);

void acceptIncomingConnections(int socketFD);
struct AcceptedSocket *acceptIncomingConnection(int socketFD);
void receiveData(int socketFD);
void receiveDataOnThread(struct AcceptedSocket *pSocket);
void sendMsgToOtherClients(int socketFD, char *buffer);
void sendConnectedUsersList(int socketFD);
bool isUsernameConnected(const char *username, int counter);


bool storePassword(const char *username, const char *password, unsigned char *salt, unsigned char *hash, int socketFD);
void hashPassword(const char *password, const unsigned char *salt, unsigned char *hash);
void printHex(const unsigned char *data, size_t length, char *out_hex);


//implementation

//sends currently connected clients to a client
void sendConnectedUsersList(int socketFD)
{
    char userList[1024] = "Connected users: ";
    bool firstUser = true;

    for (int i = 0; i < acceptedSocketsCount; i++)
    {
        if (acceptedSockets[i].acceptedSocketFD != socketFD)
        {
            if (acceptedSockets[i].username[0] != '\0')
            {
                if (!firstUser)
                {
                    strcat(userList, ", ");
                }
                strcat(userList, acceptedSockets[i].username);
                firstUser = false;
            }
        }
    }

    if (firstUser)
    {
        strcat(userList, "None");
    }
    size_t length = strlen(userList);
    if (userList[length - 1] == ',')
    {
        userList[length - 1] = '\0';
    }
    strcat(userList, "\n");
    send(socketFD, userList, strlen(userList), 0);
}

//runs receiveData on a different thread
void receiveDataOnThread(struct AcceptedSocket *pSocket)
{
    pthread_t id;
    pthread_create(&id, NULL, (void *(*)(void *))receiveData, (void *)(intptr_t)pSocket->acceptedSocketFD);
}

//connection establishmnet,data communication
void receiveData(int socketFD)
{
    char buffer[1024];
    bool firstMessage = true;
    char password[128];

    struct AcceptedSocket *pSocket = NULL;
    for (int i = 0; i < acceptedSocketsCount; i++)
    {
        if (acceptedSockets[i].acceptedSocketFD == socketFD)
        {
            pSocket = &acceptedSockets[i];
            break;
        }
    }

    while (true)
    {
        ssize_t amountReceived = recv(socketFD, buffer, 1024, 0);

        if (amountReceived > 0)
        {
            buffer[amountReceived] = '\0';

            if (firstMessage)
            {
                // first message will be the username and password
                char *username = strtok(buffer, ":");
                char *password = strtok(NULL, ":");

                if (username && password)
                {   
                    //condition check for multiple connections with the same username
                    if (isUsernameConnected(username, 0))
                    {
                        char message[256];
                        snprintf(message, sizeof(message), "Username '%s' is already connected. Rejected new connection.\n", username);
                        send(socketFD, message, strlen(message), 0);

                        printf("Username '%s' is already connected. Rejected new connection.\n", username);

                        close(socketFD);
                        removeSocket(socketFD, 0);
                        break;
                    }
                    strncpy(pSocket->username, username, sizeof(pSocket->username) - 1);
                    pSocket->username[sizeof(pSocket->username) - 1] = '\0'; 
                    firstMessage = false;

                    //generating salt and hash for the password
                    unsigned char salt[SALT_SIZE];
                    unsigned char hash[HASH_SIZE];
                    RAND_bytes(salt, SALT_SIZE);
                    hashPassword(password, salt, hash);

                    bool newUser = false;
                    newUser = storePassword(pSocket->username, password, salt, hash, socketFD);

                    FILE *file = fopen("passwords", "r");
                    if (!file)
                    {
                        perror("Error opening file");
                        close(socketFD);
                        break;
                    }

                    char line[256];
                    bool usernameExists = false;
                    bool passwordCorrect = false;

                    while (fgets(line, sizeof(line), file))
                    {
                        char stored_username[128];
                        char stored_salt[SALT_SIZE * 2 + 1];
                        char stored_hash[HASH_SIZE * 2 + 1];
                        sscanf(line, "%127[^:]:%32[^:]:%64s", stored_username, stored_salt, stored_hash);

                        if (strcmp(stored_username, pSocket->username) == 0)
                        {
                            usernameExists = true;

                            unsigned char binary_salt[SALT_SIZE];
                            for (int i = 0; i < SALT_SIZE; i++)
                            {
                                sscanf(&stored_salt[i * 2], "%2hhx", &binary_salt[i]);
                            }

                            unsigned char entered_hash[HASH_SIZE];
                            hashPassword(password, binary_salt, entered_hash);

                            char entered_hash_str[HASH_SIZE * 2 + 1];
                            printHex(entered_hash, HASH_SIZE, entered_hash_str);

                            // comparing existing password with the given one in hash form
                            if (strcmp(entered_hash_str, stored_hash) == 0)
                            {
                                passwordCorrect = true;
                            }
                            break;
                        }
                    }
                    fclose(file);

                    if (usernameExists && passwordCorrect)
                    {
                        if (!isUsernameConnected(pSocket->username, 1))
                        {
                            if (newUser == false)
                            {
                                printf("User connected: %s\n", pSocket->username);
                            }

                            const char *successMessage = "Authentication successful\n";
                            ssize_t bytesSent = send(socketFD, successMessage, strlen(successMessage), 0);
                            if (bytesSent < 0)
                            {
                                perror("Error sending success message");
                            }
                            // notifying remaining clients of the new connection
                            char notifyMessage[256];
                            char username[128];
                            strcpy(username, pSocket->username);
                            snprintf(notifyMessage, sizeof(notifyMessage), "User %s has joined the chat.\n", username);

                            for (int i = 0; i < acceptedSocketsCount; i++)
                            {
                                // printf("sent to: %s",pSocket->username);
                                if (acceptedSockets[i].acceptedSocketFD != socketFD && acceptedSockets[i].username != NULL && strlen(acceptedSockets[i].username) > 0)
                                {
                                    send(acceptedSockets[i].acceptedSocketFD, notifyMessage, strlen(notifyMessage), 0);
                                }
                            }

                            printf("Currently connected users:\n");
                            for (int i = 0; i < acceptedSocketsCount; i++)
                            {
                                if (acceptedSockets[i].acceptedSocketFD != socketFD)
                                {
                                    printf("%s\n", acceptedSockets[i].username);
                                }
                            }
                            sendConnectedUsersList(socketFD);
                        }
                        else
                        {
                            close(socketFD);
                            removeSocket(socketFD, true);
                            break;
                        }
                    }
                    else
                    {
                        const char *errorMessage = "Incorrect password\n";
                        ssize_t bytesSent = send(socketFD, errorMessage, strlen(errorMessage), 0);
                        close(socketFD);
                        break;
                    }
                }
            }
            else
            {
                if (buffer[0] == '@')
                {
                    char *recipientName = strtok(buffer + 1, "/");
                    char *privateMessage = strtok(NULL, "\0");
                    //sending a private message to a client 
                    if (recipientName && privateMessage)
                    {
                        for (int i = 0; i < acceptedSocketsCount; i++)
                        {
                            if (strcmp(acceptedSockets[i].username, recipientName) == 0)
                            {
                                char privateMsg[1024];
                                snprintf(privateMsg, sizeof(privateMsg), "(Private) %s: %s", pSocket->username, privateMessage);
                                send(acceptedSockets[i].acceptedSocketFD, privateMsg, strlen(privateMsg), 0);
                                break;
                            }
                        }
                    }
                }
                else
                {
                    if (strstr(buffer, "has disconnected"))
                    {
                        removeSocket(socketFD, false); 
                        break;
                    }
                    else
                    {
                        sendMsgToOtherClients(socketFD, buffer);
                    }
                }
            }
        }
        else if (amountReceived == 0 || (amountReceived < 0 && errno != EBADF))
        {
            removeSocket(socketFD, false);
            break;
        }
        else if (amountReceived < 0)
        {
            perror("recv bu");
            break;
        }
    }
    close(socketFD);
}


//runs receiveData on thread for each accepted connection
void acceptIncomingConnections(int socketFD)
{
    while (true)
    {
        struct AcceptedSocket *clientSocket = acceptIncomingConnection(socketFD);
        acceptedSockets[acceptedSocketsCount++] = *clientSocket;
        receiveDataOnThread(clientSocket);
    }
}

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

struct AcceptedSocket *acceptIncomingConnection(int socketFD)
{
    struct sockaddr_in clientAddress;
    socklen_t clientAddressSize = sizeof(clientAddress);
    int clientSocketFD = accept(socketFD, (struct sockaddr *)&clientAddress, &clientAddressSize);
    if (clientSocketFD < 0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddress.sin_addr, clientIP, INET_ADDRSTRLEN);

    struct AcceptedSocket *acceptedSocket = malloc(sizeof(struct AcceptedSocket));
    acceptedSocket->address = clientAddress;
    acceptedSocket->acceptedSocketFD = clientSocketFD;
    acceptedSocket->acceptedSuccessfully = clientSocketFD > 0;

    if (!acceptedSocket->acceptedSuccessfully)
    {
        acceptedSocket->error = clientSocketFD;
    }
    return acceptedSocket;
}

void sendMsgToOtherClients(int socketFD, char *buffer)
{
    struct AcceptedSocket *senderSocket = NULL;
    for (int i = 0; i < acceptedSocketsCount; i++)
    {
        if (acceptedSockets[i].acceptedSocketFD == socketFD)
        {
            senderSocket = &acceptedSockets[i];
            break;
        }
    }

    if (senderSocket)
    {
        char messageWithUsername[1024];
        snprintf(messageWithUsername, sizeof(messageWithUsername), "%s: %s", senderSocket->username, buffer);
        printf("%s\n", messageWithUsername);

        for (int i = 0; i < acceptedSocketsCount; i++)
        {
            if (acceptedSockets[i].acceptedSocketFD != socketFD)
            {
            if(!isUsernameConnected(acceptedSockets[i].username,1) && acceptedSockets[i].username != NULL && strlen(acceptedSockets[i].username) > 0){
                send(acceptedSockets[i].acceptedSocketFD, messageWithUsername, strlen(messageWithUsername), 0);
                }
                // printf("Sent to: %s\n", acceptedSockets[i].username);
            }
        }
        fflush(stdout); 
    }
}

//removing the socket and notifying other clients
void removeSocket(int socketFD, bool unAuthenticated)
{
    char disconnectedUser[128];

    for (int i = 0; i < acceptedSocketsCount; i++)
    {
        if (acceptedSockets[i].acceptedSocketFD == socketFD)
        {
            if (!unAuthenticated)
            {
                snprintf(disconnectedUser, sizeof(disconnectedUser), "%s", acceptedSockets[i].username);
            }
            // replacing the remaining sockets in array
            for (int j = i; j < acceptedSocketsCount - 1; j++)
            {
                acceptedSockets[j] = acceptedSockets[j + 1];
            }
            acceptedSocketsCount--;
            break;
        }
    }
    if (!unAuthenticated)
    {

        if (disconnectedUser[0] != '\0')
        {
            printf("User %s disconnected.\n", disconnectedUser); 

            char message[256];
            snprintf(message, sizeof(message), "User %s has disconnected\n", disconnectedUser);

            for (int i = 0; i < acceptedSocketsCount; i++)
            {
                send(acceptedSockets[i].acceptedSocketFD, message, strlen(message), 0);
            }
        }
    }
}

void hashPassword(const char *password, const unsigned char *salt, unsigned char *hash)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, salt, SALT_SIZE);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, hash, NULL);
    EVP_MD_CTX_free(mdctx);
}

void printHex(const unsigned char *data, size_t length, char *out_hex)
{
    for (size_t i = 0; i < length; i++)
    {
        sprintf(out_hex + i * 2, "%02x", data[i]);
    }
    out_hex[length * 2] = '\0';
}

//to prevent multiple connections
bool isUsernameConnected(const char *username, int counter)
{
    int count = 0;
    for (int i = 0; i < acceptedSocketsCount; i++)
    {
        // printf("User: %s\n", acceptedSockets[i].username);  
        if (strcmp(acceptedSockets[i].username, username) == 0)
        {
            count++; 
        }
    }

    if (count > counter)
    {
        return true; 
    }

    return false; 
}

//storing the authentication information in the format "username:salt:hash"
//rejects multiple connections from the same username 
bool storePassword(const char *username, const char *password, unsigned char *salt, unsigned char *hash, int socketFD)
{

    if (isUsernameConnected(username, 1))
    {
        char message[256];
        snprintf(message, sizeof(message), "Username '%s' is already connected. Rejected new connection.\n", username);
        send(socketFD, message, strlen(message), 0);

        printf("Username '%s' is already connected. Rejected new connection.\n", username);

        close(socketFD);
        removeSocket(socketFD, true);
        return false;
    }
    FILE *file = fopen("passwords", "r");
    bool newUser = false;
    if (!file)
    {
        // perror("Error opening file for reading");
        file = fopen("passwords", "w");
        if (!file)
        {
            perror("Error creating file");
            return false;
        }
        fclose(file);
        file = fopen("passwords", "r");
        if (!file)
        {
            perror("Error opening file after creation");
            return false;
        }
    }

    char line[256];
    bool usernameExists = false;

    while (fgets(line, sizeof(line), file))
    {
        char stored_username[128];
        char stored_salt[SALT_SIZE * 2 + 1];
        char stored_hash[HASH_SIZE * 2 + 1];
        sscanf(line, "%127[^:]:%32[^:]:%64s", stored_username, stored_salt, stored_hash);

        if (strcmp(stored_username, username) == 0)
        {
            usernameExists = true;

            unsigned char binary_salt[SALT_SIZE];
            for (int i = 0; i < SALT_SIZE; i++)
            {
                sscanf(&stored_salt[i * 2], "%2hhx", &binary_salt[i]);
            }

            unsigned char entered_hash[HASH_SIZE];
            hashPassword(password, binary_salt, entered_hash);

            char entered_hash_str[HASH_SIZE * 2 + 1];
            printHex(entered_hash, HASH_SIZE, entered_hash_str);

            if (strcmp(entered_hash_str, stored_hash) != 0)
            {
                close(socketFD);
                removeSocket(socketFD, true); 
            }
            break;
        }
    }
    fclose(file);

    if (!usernameExists)
    {
        file = fopen("passwords", "a");
        if (!file)
        {
            perror("Error opening file for appending");
            return false;
        }

        char salt_str[SALT_SIZE * 2 + 1];
        char hash_str[HASH_SIZE * 2 + 1];

        printHex(salt, SALT_SIZE, salt_str);
        printHex(hash, HASH_SIZE, hash_str);

        fprintf(file, "%s:%s:%s\n", username, salt_str, hash_str);
        fclose(file);

        printf("New user connected: %s\n", username);
        newUser = true;
    }
    return newUser;
}

int main()
{
    unsigned char salt[SALT_SIZE];
    unsigned char hash[HASH_SIZE];
    unsigned char confirm_hash[HASH_SIZE];
    char password[128];
    char confirm_password[128];

    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in *serverAddress = createIPv4Address("", 2000); 

    if (bind(socketFD, (const struct sockaddr *)serverAddress, sizeof(*serverAddress)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(socketFD, 10) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening for connections...\n");
    acceptIncomingConnections(socketFD);

    return 0;
}

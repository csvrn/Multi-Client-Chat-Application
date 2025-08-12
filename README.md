# Multi-Client Chat Application
This project is a multi-client chat application written in C, designed to allow multiple clients to communicate with a server concurrently. The server is responsible for managing user authentication and facilitating message exchange between connected clients.

## Features
- <strong> User Authentication: </strong> Clients are prompted for a username and password upon connecting.
  - If a username is new, the server creates a new user account, storing the password in a hashed format using the OpenSSL library for security.
  - If a username already exists, the provided password is checked against the stored credentials, and the connection is established only if the password is correct.
  - Multiple connections from the same username are not allowed.
- <strong> Real-time Messaging: </strong> Users can send and receive text messages with other connected clients.
- <strong> Private Messaging: </strong> The application supports sending direct messages to specific users.
- <strong> Notifications: </strong> Clients receive notifications about currently connected users when they join. Notifications are also shared during runtime when specific clients connect or disconnect.
- <strong> Timestamps: </strong> All messages include timestamps to show when they were sent.

## Implementation Details
The project utilizes multithreading to handle multiple clients simultaneously, with each client managed by a separate thread. This approach allows for concurrent message exchange without blocking. The application uses a simple command-line interface to focus on core chat functionality.

## Challenges
- <strong> Handling Multiple Clients: </strong> Multithreading with pthread was used to manage multiple client connections independently.
- <strong> Synchronization: </strong> Mutexes were implemented to synchronize access to shared resources, such as the list of connected clients, to prevent race conditions.
- <strong> Secure Authentication: </strong> The OpenSSL library was used to securely handle user credentials by hashing passwords.

## Getting Started
To run the application, you will need to compile the C source code. The project requires linking with the pthread and crypto libraries. A sample compilation command is shown in the runtime screenshots, for example: 
- Server side:
```
gcc program.c -o program.out -lpthread -lcrypto
```
- Client side:
```
//client side does not require the -lcrypto flag since it does not use OpenSSL functions 
gcc program.c -o program.out -lpthread
```

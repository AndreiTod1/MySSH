This project is a simple and secure client-server system that lets users remotely run shell commands while keeping their data safe. The client connects to the server, logs in, and sends commands, which the server executes and sends back the results.

To keep everything private, the system uses encryption so that no one can see what commands are being sent. It also protects user passwords by storing them securely.

Main features: 

Client-Server Architecture

A TCP-based server listens for incoming client connections.
The client securely connects and communicates with the server.

  End-to-End Encryption
Elliptic Curve Diffie-Hellman (ECDH) is used for secure key exchange.
AES-256-GCM encryption ensures all data transmissions remain confidential.
  
  User Authentication & Registration
Users can register and log in using credentials.
Passwords are stored securely using Argon2 hashing.
 
  Secure Remote Command Execution
Supports running shell commands on the server securely.
Includes redirection (>, >>, <), pipes (|), and logical operators (&&, ||).
  
  Multi-Client Support
Manages multiple concurrent client sessions with unique IDs.
Maintains per-client working directories.
 
  Error Handling & Validation
Prevents invalid command sequences.
Ensures proper syntax and logical operator usage.

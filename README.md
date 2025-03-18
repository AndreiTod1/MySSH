🔒 Secure Remote Command Execution
A lightweight and secure client-server system that lets users remotely run shell commands while keeping their data private. The client logs in, sends commands, and the server executes them—all over an encrypted connection.

💡 Perfect for secure remote access, administration, or as a light alternative to SSH.

🚀 Features

🖧 Client-Server Architecture
A TCP server listens for connections, and clients securely connect to interact.

🔐 End-to-End Encryption
Uses Elliptic Curve Diffie-Hellman (ECDH) for secure key exchange.
Encrypts all communication with AES-256-GCM for complete privacy.

👤 User Authentication & Registration
Supports user sign-up and login.
Passwords are stored safely using Argon2 hashing.

💻 Secure Remote Command Execution
Run shell commands remotely, just like on a local terminal.
Supports:
✅ Redirection (>, >>, <)
✅ Pipes (|)
✅ Logical operators (&&, ||)

👥 Multi-Client Support
Handles multiple users at the same time, with each having its own working directory.

🛠 Smart Error Handling & Validation
Prevents invalid command sequences.
Ensures correct syntax and operator usage.

🏗 How It Works

1️⃣ Start the Server
# cargo run -- server

2️⃣ Run the Client
# cargo run -- client

3️⃣ Login or Register
# register username:password   # Sign up  
# username:password            # Login  

4️⃣ Execute Commands
example:
# pwd
# cd .. 
# echo Rust is cool; cat file.txt | grep cool




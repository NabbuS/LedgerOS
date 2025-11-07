🔒 SecureLedgerOS A lightweight **File Integrity Monitoring System** written in C that automatically detects and logs file **access**, **modification**,**deletion** and **creation** events using **cryptographic hash chaining**. Designed to ensure tamper-proof logging and transparent file activity tracking — ideal for system security and audit purposes.

⚙️ Features  Monitors a target folder for: - New file creation - File access (opening a file) - File modification - File deletion 
 ✅ Generates unique **SHA-256 hashes** for each event. 
 ✅ Maintains a **linked hash chain ledger** for immutability. 
 ✅ Raises alerts when tampering is detected. 
 ✅ Works across platforms (Windows / Linux). 

 🧠 Tools Used 
**C Language** - Core logic and system-level programming
**OpenSSL** - Cryptographic hashing (SHA-256) 
**GCC / MinGW** - Compilation 
**VS Code** - Development environment 

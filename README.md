# buddy

Buddy is a C++/Qt library and command line utility to embed GPG signatures into the headers of ELF binaries. 
Instead of storing detached signatures or encrypting the binaries themselves, Buddy can store detached signatures in the ELF header of a binary.  

Command line utility usage:  
1. List your available keys using gpg --list-keys  
2. Sign a file using `buddy --sign [file] [key]` (the key should be the full 160-bit ID)  
3. Check the file's signatures using `buddy --check [file]`  
4. Remove a signature from a file using `buddy --remove [file] [key]`  
5. Clear all signatures from a file using `buddy --clear-all-signatures [file]` 

You can sign a file using multiple keys, but only one at a time currently. Duplicate keys will be ignored.  

Currently only supports 64-bit ELF binaries.  
Requires Qt, libqgpgme and libgpgme++  

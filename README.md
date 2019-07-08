# buddy
Sign ELF binaries using GPG keys  

Buddy is a C++/Qt library and command line utility to embed GPG signatures into the headers of ELF binaries. 
Instead of storing detached signatures or encrypting the binaries themselves, Buddy can store detached signatures in the ELF header of a binary.  

Currently only supports 64-bit ELF binaries.  
Requires Qt, libqgpgme and libgpgme++

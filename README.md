# TextEncrypt

USAGE: This app is designed to encrypt and decrypt text

### INSTRUCTIONS
1. To run the app, launch RC4-APP.exe. Enter a 10-character encryption key in hexadecimal format (0-9, A-F).
2. Select an option (1-3). 
	- Option 1 lets you enter text from within the console and then encrypts that text into console.encrypted file.
	- Option 2 lets you enter a text file name then encrypts its content into textFileName-txt.encrypted.
	- Option 3 lets you decrypt a file and the output will be msg-decrypted.txt if the original message was from a file input or console.txt if the text input was from the console.

Technical specifications:
The first initialization vector (IV) is placed on the first 4 bytes of the encrypted message. This is the only IV sent in the file. The other IVs are calculated automatically with an LFSR with the decoded IV from the encrypted file. The output length of a message is standardized (to a full keystream length so 213*4 bits) so it is not possible to deduct the length of the encrypted message (plaintext vulnerability).

i.e. encrypted message:
639B248E04017D6C693EE96ED4A81AE76C0A5B3178083A31EF4FD7EA4F1267E7255B1288E29BA1C7400DB9F6559283261184135C1B64A1DC9BD60B52F7B1D30622E3B4B446BD41B7AEF77725BBEA09A4E8E3708595A8D60135CE2E94A1B33C70C082C875312D460787DABEE7C8786C

IV is 0x639B248E


### ROADMAP
- DONE	Encrypt/Decrypt text message with RC4 algorithm
- DONE	Encrypt/Decrypt message contained in a txt file
- DONE	Randomize first IV
- DONE	Multikey to encrypt/decrypt message (first generated keystream is with key #0 and other keystreams are with other keys)

### MultiKey Encrypt
- Place the file "keys.txt" in the same directory of the .exe file and replace the keys with 10 characters hex keys
- DO NOT write keys in a different format than HEX as the program maycrash
- The program will automatically encrypt each part of the message (each 213 hex characters) with a different key until the end key is reached and the rest of the message will be encrypt with this key

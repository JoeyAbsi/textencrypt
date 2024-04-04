#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <windows.h>
#include <ctime>
#include <chrono>
#include <stdlib.h>
#include <random>
#include <vector>
#include <sstream>
#include <ctime>
#include <chrono>

using namespace std;

#pragma warning(disable : 4996)

//GLOBAL VARIABLES
uint8_t rc4_keystream[469] = {};
vector<unsigned char> cipherText;
vector<unsigned char> clearText;
vector<unsigned char> cipherVector;
uint8_t d_mi[4] = {};
uint8_t rc4_key[9] = {};
bool firstRun = true;
uint32_t lfsr = 0;
uint64_t key;

static void keyAppend(uint64_t key) {
    // Appends encryption key (uint64_t) to key array 

    for (int i = 0; i < 5; i++)
        rc4_key[i] = (key >> (40 - (i + 1) * 8)) & 0xFF;
}

static void rc4_dmr(uint64_t key, uint8_t d_mi[4]) {
    // Generates RC4 keystream used to encrypt/decrypt data with key array

    uint8_t  S[256], K[256];
    uint32_t i, j, k;
    j = 0;

    keyAppend(key);

    for (i = 5; i < 9; ++i) {
        rc4_key[i] = d_mi[i - 5];   // append IV bytes
    }

    for (i = 0; i < 256; ++i) {
        K[i] = rc4_key[i % 9];
    }

    for (i = 0; i < 256; ++i) {
        S[i] = i;
    }

    for (i = 0; i < 256; ++i) {
        j = (j + S[i] + K[i]) & 0xFF;

        uint8_t temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    i = j = 0;

    for (k = 0; k < 469; ++k) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        uint8_t temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        rc4_keystream[k] = S[(S[i] + S[j]) & 0xFF];
    }

    firstRun = false;
}

static void LFSR() {
    // Generates first IV randomly and computes next IVs from the first IV

    if (firstRun) {
        //if the algo is ran the first time, generate a random IV
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<uint32_t> dis(0, UINT32_MAX);
        lfsr = dis(gen);
    }
    else {
        for (uint8_t cnt = 0; cnt < 32; cnt++) {
            // Polynomial is C(x) = x^32 + x^4 + x^2 + 1
            uint32_t bit = ((lfsr >> 31) ^ (lfsr >> 3) ^ (lfsr >> 1)) & 0x1;
            lfsr = (lfsr << 1) | (bit);
        }
    }

    //Append generated IV to d_mi array
    for (int i = 0; i < 4; ++i) {
        d_mi[i] = (lfsr >> (24 - i * 8)) & 0xFF;
        
        if(firstRun)
            cipherText.push_back(d_mi[i]);
    }
}

static void clearTextAppend(string clearText, int option) {
    // Store ASCII values of text into cipherVector
    
    if ((option == 1) || (option == 2)) {
        for (char c : clearText)
            cipherVector.push_back(static_cast<unsigned char>(c));
    }
    else if (option == 3) {
        for (size_t i = 0; i < clearText.length(); i += 2) {
            string byteString = clearText.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(stoi(byteString, nullptr, 16));
            cipherVector.push_back(byte);
        }
    }
}

static string textAppend(vector<unsigned char> cipherVector) {
    // Reconstruct original string from cipherVector

    string originalString(cipherVector.begin(), cipherVector.end());
    return originalString;
}

static void cipher(vector<unsigned char> cipherVector) {
    // Encrypts data

    int availableKeystream = 213; //keystream effective bytes: 469-256 = 213

    LFSR();
    rc4_dmr(key, d_mi);

    if (cipherVector.size() <= availableKeystream) {
        if (cipherVector.size() < availableKeystream) {
            for (int i = 0; i < (availableKeystream - cipherVector.size()); i++) {
                //ajout de bytes nuls (espaces) pour standardiser la taille du message crypté (sécurité contre plaintext attack)
                cipherVector.push_back(0x00);
            }
        }
        
        for (int i = 0; i < cipherVector.size(); i++)
            cipherText.push_back(cipherVector[i] ^ rc4_keystream[i + 256]);
    }
    else {
        //Si le texte est trop long, il faut regénerer un IV et un keystream à chaque 213 bytes
        double numberOfGeneratedKeystream = ceil(cipherVector.size() / static_cast<double>(availableKeystream));

        for (int i = 0; i < numberOfGeneratedKeystream; i++) {
            int maxJ = (i == numberOfGeneratedKeystream - 1) ? cipherVector.size() % availableKeystream : availableKeystream;
            
            for (int j = 0; j < maxJ; j++)
                cipherText.push_back(cipherVector[(i* availableKeystream) + j] ^ rc4_keystream[j + 256]);
            
            if (i < numberOfGeneratedKeystream - 1) {
                LFSR();
                rc4_dmr(key, d_mi);
            }
        }        
    }
}

static void decipher(vector<unsigned char> cipherVector) {
    // Decrypts data

    uint8_t extractedIV[4] = {};
    vector<unsigned char> cipherTemp;
    int availableKeystream = 213; //469-256 = 213
    double numberOfGeneratedKeystream = ceil(cipherVector.size() / static_cast<double>(availableKeystream));

    if (cipherText.size() == 0) {
        cipherText = cipherVector;
    }

    //Extract first IV
    for (int i = 0; i < 4; i++)
        extractedIV[i] = cipherText[i];

    for (int i = 0; i < 4; i++) {
        d_mi[i] = extractedIV[i];
        lfsr |= d_mi[i] << (8 * (3 - i));
    }
    
    for (int j = 0; j < cipherText.size() - 4; j++)
        cipherTemp.push_back(cipherText[j + 4]);

    //Initialize keystream
    rc4_dmr(key, extractedIV);
    
    size_t maxI = (cipherText.size() < cipherVector.size()) ? cipherVector.size() : cipherTemp.size();
    size_t maxI2 = (numberOfGeneratedKeystream > 1) ? availableKeystream : maxI;

    for (int j = 0; j < numberOfGeneratedKeystream; j++)
    {
        //Decryption
        if (numberOfGeneratedKeystream == 1) {
            for (int i = 0; i < maxI2; i++)
                clearText.push_back(cipherTemp[i] ^ rc4_keystream[i + 256]);
        }
        else if (j == (numberOfGeneratedKeystream - 1)) {
            for (int i = 0; i < (cipherTemp.size() - availableKeystream *j); i++)
                clearText.push_back(cipherTemp[i + availableKeystream *j] ^ rc4_keystream[i + 256]);
        }
        else {
            for (int i = 0; i < maxI2; i++)
                clearText.push_back(cipherTemp[i + j* availableKeystream] ^ rc4_keystream[i + 256]);
        }

        //Compute Next IV and generate new keystream
        LFSR();
        rc4_dmr(key, d_mi);
    }

    //Remove null bytes at the end of message
    unsigned char nullBytes = 0x00;
    clearText.erase(remove_if(clearText.begin(), clearText.end(), [&](unsigned char byte) {
        return byte == nullBytes;
        }), clearText.end());
}

string getCurrentDateTimeAsString() {
    // Get date and time and output it as a string

    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm local_tm = *std::localtime(&time_t_now);
    stringstream ss;
    ss << std::put_time(&local_tm, "%Y-%m-%d_%H-%M-%S");
    return ss.str();
}

string filenameExtract(string filename, int option) {
    // Extract file name from input

    string filenameExtracted;
    size_t dotPos = filename.find(".");
    size_t dotPosEncrypted = filename.find(".encrypted");

    if (option == 2) {
        string fileName = filename.substr(0, dotPos);
        string extension = filename.substr(dotPos + 1); // Extract the file extension
        filenameExtracted = fileName + "-" + extension + ".encrypted";
    }
    else {
        size_t lastDash = filename.find_last_of("-");
        string fileName = filename.substr(0, lastDash);
        string extension = filename.substr(lastDash + 1, dotPosEncrypted - lastDash - 1);
        filenameExtracted = fileName + "-decrypted." + extension;
    }

    return filenameExtracted;
}

int main() {
    int option;
    string key2;

    cout << "Please enter encryption key in HEX format: 0x";
    cin >> hex >> key2;

    if (key2.length() < 10) {
        //Add zeros if the key provided is under 10 characters
        key2 += std::string(10 - key2.length(), '0');
        istringstream stream(key2);
        stream >> hex >> key;
    }
    else if (key2.length() > 10) {
        cout << "Key input is too long. Exiting program...\n";
        return 0;
    }
    else {
        istringstream stream(key2);
        stream >> hex >> key;
    }

    cout << "Select your service:\n1 - Encrypt text from console\n2 - Encrypt from text file\n3 - Decrypt from text file\nSelection: ";
    cin >> option;


    if (option == 1) {
        string clearText;
        string filenameEnc = "console.encrypted";

        cout << "Enter text to encrypt: ";
        cin.ignore();
        getline(cin, clearText);
        clearTextAppend(clearText, option);

        cipher(cipherVector);

        fstream textFileEncrypted(filenameEnc, ios::out | ios::binary);

        for (char c : textAppend(cipherText))
            textFileEncrypted << hex << uppercase << setw(2) << setfill('0') << static_cast<int>(static_cast<unsigned char>(c));

        cout << "\nFile encrypted successfully! Encrypted file is " << filenameEnc << "\n";
    }
    else if (option == 2) {
        string filenameToEncrypt;
        string filenameEnc;
        string text;
        char c;

        cout << "Enter filename to encrypt: ";
        cin.ignore();
        getline(cin, filenameToEncrypt);

        filenameEnc = filenameExtract(filenameToEncrypt, option);

        fstream textFileClear(filenameToEncrypt, ios::in);
        fstream textFileEncrypted(filenameEnc, ios::out | ios::binary);

        while(textFileClear.get(c) {
            text += c;
        }
        clearTextAppend(text, option);

        cipher(cipherVector);

        for (char c : textAppend(cipherText))
            textFileEncrypted << hex << uppercase << setw(2) << setfill('0') << static_cast<int>(static_cast<unsigned char>(c));

        cout << "\nFile encrypted successfully! Encrypted file is " << filenameEnc << "\n";
    }
    else if (option == 3) {
        string filenameEnc;
        string filenameDec;
        string text;

        cout << "Enter filename to decrypt: ";
        cin.ignore();
        getline(cin, filenameEnc);

        if (filenameEnc != "console.encrypted")
            filenameDec = filenameExtract(filenameEnc, option);
        else
            filenameDec = "console.txt";

        fstream textFileEncrypted(filenameEnc, ios::in| ios::binary);
        fstream textFileDecrypted(filenameDec, ios::out | ios::trunc);

        getline(textFileEncrypted, text);
        clearTextAppend(text, option);

        decipher(cipherVector);
        textFileDecrypted << textAppend(clearText);
        cout << "\nFile decrypted successfully! Decrypted file is " << filenameDec << "\n";
    }
    else
        cout << "Selected option is invalid. Exiting program...\n";

    system("pause");
    return 0;
}

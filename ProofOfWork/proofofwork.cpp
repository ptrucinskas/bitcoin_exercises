#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <openssl/sha.h>

using namespace std;

// Converts int32 to uchar array of bytes. (Little endian)
unsigned char* getIntegerBytes(int integer){
    unsigned char *bytes = new unsigned char[4];
    for(int i = 0; i < 4; i++)
        *(bytes + i) =(integer >> 8*i)& 0xFF;
    return bytes;
}

// Converts int32 to uchar array of bytes. (Big endian)
unsigned char* getBytes(int integer){
    unsigned char *bytes = new unsigned char[4];
    for(int i = 0; i < 4; i++)
        *(bytes + (3 - i)) = (integer >> 8*i) & 0xFF;
    return bytes;
}

// Converts hex in string to uchar array of bytes.
unsigned char* getHexHashBytes(string hex){
    unsigned char *bytes = new unsigned char[hex.length()/2];
    for(int i = 0; i < hex.length()/2; i++)
        *(bytes + i) = (char)stoi(hex.substr(hex.length() - (i+1)*2, 2), nullptr, 16);
    return bytes;
}

// Returns hash as an unsigned char array.
unsigned char* getHash(unsigned char * input, int size){
    //unsigned char *reverseInput = new unsigned char[size];
    //for(int i = 0; i < size; i++)
    //    *(reverseInput+i)=*(input + (size-1-i));
    unsigned char *hash = new unsigned char[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, size);
    SHA256_Final(hash, &sha256);

    return hash;
}

// Returns hash of the block
unsigned char* returnBlockHash(int v, string prev_block, string merkle_root, int time, int bits, int nonce) {
    unsigned char *header = new unsigned char[80];
    unsigned char *tmp_version = getIntegerBytes(v);
    unsigned char *tmp_prev_block = getHexHashBytes(prev_block);
    unsigned char *tmp_merkle_root = getHexHashBytes(merkle_root);
    unsigned char *tmp_time = getIntegerBytes(time);
    unsigned char *tmp_bits = getIntegerBytes(bits);
    unsigned char *tmp_nonce = getIntegerBytes(nonce);

    for (int i = 0; i < 4; i++)
        *(header + i) = *(tmp_version + i);

    for (int i = 4; i < 36; i++)
        *(header + i) = *(tmp_prev_block + (i - 4));

    for(int i = 36; i < 68; i++)
        *(header + i) = *(tmp_merkle_root + (i - 36));

    for(int i = 68; i < 72; i++)
        *(header + i) = *(tmp_time + (i - 68));

    for(int i = 72; i < 76; i++)
        *(header + i) = *(tmp_bits + (i - 72));

    for(int i = 76; i < 80; i++)
        *(header + i) = *(tmp_nonce + (i - 76));

    // At this point header array contains all 80 concatenated bytes of the header.

    return getHash(getHash(header, 80) , 32);
}


// Returns whether the header hash is valid.
bool checkBlockHash(unsigned char * hash, int nBits){
    unsigned char * reversedHash = new unsigned char[32];
    for(int i = 0; i < 32; i++)
        *(reversedHash + i) = *(hash + (32 - i));

    unsigned char *nBitsBytes = getBytes(nBits);
    int bytesInTarget = (int) *nBitsBytes;

    unsigned char *target = new unsigned char[bytesInTarget];
    *(target + 0) = *(nBitsBytes + 1);
    *(target + 1) = *(nBitsBytes + 2);
    *(target + 2) = *(nBitsBytes + 3);

    for(int i= 3; i < bytesInTarget; i++)
        *(target + i) = 0;

    // Target now should contain target treshold bytes.

    // This number of most significant bytes in hash should be empty.
    int empty = 32 - bytesInTarget;
    for(int i = 0; i < empty; i++)
        if(*(reversedHash + i) != 0)
            return false;

    // The hash left should be same size as target.
    // We compare the most significant byte of each.
    for(int i = 0; i < bytesInTarget; i++)
        if(*(reversedHash + (empty + i)) == *(target + i))
            continue;
        else if(*(reversedHash + (empty + i)) < *(target + i))
            return true;
        else
            return false;
}

int main(){
    int protocol_version = 0x20000000;
    string previous_block_hash =     "0000000000000000007962066dcd6675830883516bcf40047d42740a85eb2919";
    string transaction_merkle_root = "31951c69428a95a46b517ffb0de12fec1bd0b2392aec07b64573e03ded31621f";
    int timestamp = 1513622125;
    int bits = 402691653;
    int nonce = 1560058197-100;
    bool correct = false;

    unsigned char *hash;


    while(!correct && nonce < 1560058197 + 100){
        cout << "Nonce incorrect: " << nonce << endl;
        nonce++;
        hash = returnBlockHash(protocol_version, previous_block_hash,
                               transaction_merkle_root, timestamp,
                               bits, nonce);
        correct = checkBlockHash(hash, bits);
    }


    cout << "Found the right nonce: " << nonce << endl;

    return 0;
}



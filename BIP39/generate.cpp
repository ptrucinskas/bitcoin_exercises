#include <iostream>
#include <fstream>

using namespace std;

#include <iomanip>
#include <sstream>
#include <string>
#include <openssl/sha.h>
#include <bitset>

unsigned char* generateEntropy(int size){
    unsigned char gen;
    unsigned char *buf = new unsigned char[size / 8];
    ifstream urandom("/dev/urandom", ios::in|ios::binary);
    if(urandom){
        urandom.read(reinterpret_cast<char*> (buf), size/8);
        urandom.close();
    }else{
        cerr << "Failed to open /dev/urandom" << std::endl;
    }

    return buf;
}

unsigned char* getHash(unsigned char * entropy, int size){
    unsigned char *hash = new unsigned char[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, entropy, size/8);
    SHA256_Final(hash, &sha256);

    return hash;
}

unsigned char getChecksum(unsigned char * byte, int size){
    unsigned char checksum = *byte;
    checksum >> (8 - size/32) & 0xFF;
    return checksum;
}

stringstream getBinaryEntropy(unsigned char * entropy, int size){
    stringstream binary_entropy;
    unsigned char byte;
    unsigned char bits[8];
    for (int i = 0; i < size/8; i++) {
        byte = *(entropy + i);

        for (int j = 0; j < 8; j++)
            bits[7-j] = (int)((byte >> j) & 1);
        for (int j = 0; j < 8; j++)
            binary_entropy << (int)bits[j];
    }
    return binary_entropy;
}

stringstream getBinaryChecksum(unsigned char checksum, int size){
    stringstream binary_checksum;

    unsigned char bits[8];
    for (int i = 0; i < size/32; i++)
        bits[(size/32-1)-i] = (int)((checksum >> i) & 1);
    for (int i = 0; i < size/32; i++)
        binary_checksum << (int)bits[i];

    return binary_checksum;
}

unsigned short * getWordIndexes(string entropy){

    unsigned char index_count = entropy.length()/11;
    unsigned short * indexes = new unsigned short[index_count];
    string index;
    for(int i = 0; i < index_count; i++){
        index = entropy.substr(i * 11 , 11);
        *(indexes+i) = (short)bitset<16>(index).to_ulong();
    }
    return indexes;
}

string getWordlist(unsigned short * indexes, int count){
    ifstream italian("italian.txt");
    string italian_words[2048];
    for(int i = 0; i < 2048; i++)
        italian >> italian_words[i];

    string wordlist;
    for(int i = 0; i < count; i++)
        wordlist += italian_words[*(indexes + i)] + " ";

    wordlist.erase(wordlist.length()-1, 1);

    return wordlist;
}

int main(int argc, char *argv[]){
    int size = 256;

    unsigned char * ent = generateEntropy(size);

    cout << size/8 << " random bytes" << endl;
    for (unsigned int i = 0; i < size / 8; i++) {
        cout << (int) *(ent+i) << " ";
    }

    cout << "\n\n";

    unsigned char * hash = getHash(ent, size);

    unsigned char checksum = getChecksum(hash, size);


    stringstream ss_hash;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss_hash << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    cout << "Hash from the random bytes" << endl;
    cout << ss_hash.str() << "\n\n";

    cout << "First " << size/32 << " bits of hash as checksum" << endl;
    cout << (int)checksum << "\n\n";


    stringstream binary_entropy = getBinaryEntropy(ent, size);

    cout << "Entropy in binary" << endl;
    cout << binary_entropy.str() << "\n\n";

    stringstream binary_checksum = getBinaryChecksum(checksum, size);

    binary_entropy << binary_checksum.str();

    cout << "Binary checksum" << endl;
    cout << binary_checksum.str() << "\n\n";

    cout << "Entropy in binary with checksum appended" << endl;
    cout << binary_entropy.str() << "\n\n";


    cout << "Word indexes" << endl;
    unsigned short * word_indexes = getWordIndexes(binary_entropy.str());

    for(int i = 0; i < binary_entropy.str().length()/11; i++)
        cout << *(word_indexes+i) << " ";
    cout << "\n\n";

    string wordlist = getWordlist(word_indexes, binary_entropy.str().length()/11);

    cout << "Mnemonic sentence" << endl;
    cout << wordlist << endl;

    return 0;
}


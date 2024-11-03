#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <cstring>
#include <unistd.h>
#include <pthread.h>
#include <vector>
#include <crypto++/aes.h>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/filters.h>
#include <crypto++/modes.h>
#include <cryptopp/base64.h>

#include <mutex>

using namespace CryptoPP;

#define PORT 8001   
#define BUFFER_SIZE 4096

RSA::PrivateKey privateKey;
RSA::PublicKey publicKey;
RSA::PublicKey otherPublicKey;
std::mutex keyMutex;
std::mutex sendMutex;

// Generate Keys RSA
void GenerateKeys() {
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 2048);
    privateKey = RSA::PrivateKey(params);
    publicKey = RSA::PublicKey(params);
}

bool isOtherPublicKeyInit = false;

// Send Public Key RSA to server
void sendPublicKey(int sock, RSA::PublicKey &publicKey) 
{
    std::lock_guard<std::mutex> lock(sendMutex);        // lock mutex thread for collect all
    
    std::string pubKeyStr;
    StringSink sink(pubKeyStr);
    publicKey.Save(sink);

    int size = pubKeyStr.size();
    send(sock, &size, sizeof(size), 0);     // send size of key
    send(sock, pubKeyStr.c_str(), size, 0); // send key
    std::cout << "Sending public key of size: " << size << std::endl;
}

// Receive Public Key RSA from server
bool receivePublicKey(int sock, RSA::PublicKey &otherPublicKey) 
{
    std::lock_guard<std::mutex> lock(keyMutex);         // lock mutex thread for collect all
    int size = 0;
    if (recv(sock, &size, sizeof(size), 0) <= 0)        // receive size of public key
    {
        std::cerr << "Failed to receive size of public key" << std::endl;
        return false ;
    }

    std::vector<byte> buffer(size);                     // create vector of bytes buffer
    if (recv(sock, buffer.data(), size, 0) <= 0)        // receive public key
    {
        std::cerr << "Failed to receive public key" << std::endl;
        return false;
    }

    StringSource source(buffer.data(), buffer.size(), true); // collect raw data in public key
    try 
    {
        
        otherPublicKey.Load(source);                    // load data
        std::cout << "Received public key of size: " << size << " bytes" << std::endl;
        std::cout << "Public Key: " << std::string(buffer.begin(), buffer.end()) << std::endl; // Output key in string form
        isOtherPublicKeyInit = true;
    } 
    catch (const Exception& e) 
    {
        std::cerr << "Failed to load public key: " << e.what() << std::endl;
        return false;
    }

    if(!isOtherPublicKeyInit)
    {
        std::cerr << "Cannot encrypt message: other public key not init" << std::endl;
    }
    std::string ack = "KEY_RECEIVED";
    send(sock, ack.c_str(), ack.size(), 0);
    return true;
}   



// Encrypt using AES for message
std::string encryptAES(const std::string& plainText, const byte* key, const byte* iv) 
{
    std::string cipherText;
    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
    StringSource(plainText, true, new StreamTransformationFilter(encryption, new StringSink(cipherText)));      // load and serialize cipherText data
    return cipherText;
}

// Decrypt using AES for message
std::string decryptAES(const std::string& cipherText, const byte* key, const byte* iv) 
{
    std::string decryptedText;
    try 
    {
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource(cipherText, true, new StreamTransformationFilter(decryption, new StringSink(decryptedText)));  // load and serialize decryptedText data
    } 
    catch (const Exception& e) 
    {
        std::cerr << "Decryption Error: " << e.what() << '\n';
    }
    return decryptedText;
}

// Encrypt message using RSA
std::string encryptRSA(const byte* key, size_t keySize, const RSA::PublicKey& publicKey) 
{
    AutoSeededRandomPool rng;       // generate symbols for encryption
    std::string cipherText;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);  // encryptor for public Key
    StringSource ss(key, keySize, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(cipherText))); // load, serialize data ciphertext
    return cipherText;
}

// Decrypt message using RSA
std::string decryptRSA(const std::string& cipherText, RSA::PrivateKey& privateKey) 
{
    std::string decryptedText;
    try 
    {
        AutoSeededRandomPool rng;       // generate symbols for decryption
        RSAES_OAEP_SHA_Decryptor decryptor(privateKey);     // decryptor for private key
        StringSource ss(cipherText, true, new PK_DecryptorFilter(rng, decryptor, new StringSink(decryptedText)));       // load and serialize data for decrypted text
    } 
    catch (const Exception& e) 
    {
        std::cerr << "RSA decryption Error: " << e.what() << std::endl;
    }
    return decryptedText;
}

// Receive messages
void* receive_message(void* sock) 
{

    int server_sock = *(int*) sock;
    char buffer[BUFFER_SIZE] = {0};
    
    while (true)
    {
        int msgSize = 0;
        int bytesReceived = recv(server_sock, &msgSize, sizeof(msgSize), 0);
        if(bytesReceived <= 0)
        {
            std::cerr << "Disconnected from server. " << std::endl;
            break;
        }

        if(msgSize < 0 || msgSize > BUFFER_SIZE)
        {
            std::cerr << "Receive invalid message size: " << msgSize << std::endl;
            continue;
        }

        std::vector<byte>buffer(msgSize);       // collect bytes for size msgSize
        int totalBytesReceive = 0;
        while(totalBytesReceive < msgSize)
        {
            int bytes = recv(server_sock, buffer.data() + totalBytesReceive, msgSize - totalBytesReceive, 0);
            if(bytes <= 0)
            {
                std::cerr << "error receiving message data" << std::endl;
                break;
            }
            totalBytesReceive += bytes;
        }
        if(totalBytesReceive < msgSize)
        {
            std::cerr << "Received incomplete message. " << std::endl;
            continue;
        }
        // recv(server_sock, buffer.data(), msgSize, 0);


        // calculating receive message data
        std::string encryptedAESKey (reinterpret_cast<char*>(buffer.data()), 256);
        std::string iv(reinterpret_cast<char*>(buffer.data() + 256), AES::BLOCKSIZE);
        std::string encryptedMessage(reinterpret_cast<char*>(buffer.data() + 256 + AES::BLOCKSIZE), msgSize - (256 + AES::BLOCKSIZE));

        std::string decryptedAESKey = decryptRSA(encryptedAESKey, privateKey);
        if(decryptedAESKey.empty())
        {
            std::cerr << "Failed to decrypt AES key" << std::endl;
            continue;
        }
        std::string decryptedMessage = decryptAES(encryptedMessage, (const byte *)decryptedAESKey.data(), (const byte *)iv.data());
        std::cout << "Message from another client: " << decryptedMessage << std::endl;
    }
    
    return nullptr;
    

}

int main() 
{
    int sock = 0;
    struct sockaddr_in serv_addr;

    GenerateKeys(); // Generate RSA keys for the client

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        std::cerr << "Error creating socket" << std::endl;
        return 0;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) 
    {
        std::cerr << "Invalid address or address not supported" << std::endl;
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) 
    {
        std::cerr << "Connection failed. Error code: " << errno << std::endl;
        return -1;
    }
    
    std::cout << "Connected to server." << std::endl;

    
    sendPublicKey(sock, publicKey);
    receivePublicKey(sock, otherPublicKey);
    
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, nullptr, receive_message, (void*)&sock) != 0) 
    {
        std::cerr << "Failed to create thread." << std::endl;
        return -1;
    }
    

    

    
    while (true) {
        std::string client_message;
        std::cout << "Client: ";
        std::getline(std::cin, client_message);
        if (client_message.empty()) continue; // Skip empty messages

        byte aesKey[AES::DEFAULT_KEYLENGTH];        // init aesKey size
        byte iv[AES::BLOCKSIZE];                    // init iv block size
        AutoSeededRandomPool rng;                   // generate random symbol for aesKey and IV 
        rng.GenerateBlock(aesKey, sizeof(aesKey)); // Generate AES key
        rng.GenerateBlock(iv, sizeof(iv));   // Generate IV
        
        // Отладка: Проверка публичного ключа другого клиента
        std::string otherPublicKeyStr;     
        StringSink sink(otherPublicKeyStr);     // serialize otherPublicKeyStr for debug
        otherPublicKey.Save(sink);              
        
        std::cout << "Using other client's public key of size: " << otherPublicKeyStr.size() << " bytes for encryption" << std::endl;
        std::cout << "Other Public Key: " << otherPublicKeyStr << std::endl;

        {
            std::lock_guard<std::mutex> lock(keyMutex);
            std::string encrypted_message = encryptAES(client_message, aesKey, iv);     // encrypt message  using aes
            std::string encryptedAESKey = encryptRSA(aesKey, sizeof(aesKey), otherPublicKey);       // encrypt aes key using RSA

            std::string total_message = encryptedAESKey + std::string((char*)iv, AES::BLOCKSIZE) + encrypted_message;

            int msg_size = total_message.size();
            send(sock, &msg_size, sizeof(msg_size), 0);
            send(sock, total_message.c_str(), msg_size, 0);
            std::cout << "Message sent to server." << std::endl;
        }
        
    }
    pthread_join(recv_thread, nullptr);
    close(sock);
    return 0;
}


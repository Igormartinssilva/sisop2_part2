#include "header/client.hpp"

Client::Client() {
    srand(time(NULL));
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        std::cerr << "Error opening socket" << std::endl;
        exit(EXIT_FAILURE);
    }
    this->sequence_number = 1;
    memset(&serv_addr, 0, sizeof(serv_addr));
}

Client::~Client() {
    receivingThread.join();
}

void Client::setMainServer(std::string ip, int port) {
    struct sockaddr_in mainServerAddress;
    memset(&mainServerAddress, 0, sizeof(mainServerAddress));
    mainServerAddress.sin_family = AF_INET;
    mainServerAddress.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &(mainServerAddress.sin_addr));

    serv_addr = mainServerAddress;
    
    //std::cout << "Main server set to " << ip << ":" << port << std::endl;
}

void Client::setServer(const char *hostname) {
    struct hostent *server = gethostbyname(hostname);
    if (server == nullptr) {
        std::cerr << "ERROR, no such host" << std::endl;
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr = *((struct in_addr *)server->h_addr);
    
    receivingThread = std::thread(&Client::processReceiving, this);
}

int Client::sendPacket(twt::PacketType type, uint16_t timestamp, const std::string& payload) {
    twt::Packet packet;
    packet.type = static_cast<uint16_t>(type); 
    packet.timestamp = timestamp; 
    packet.sequence_number = sequence_number ++;
    std::memcpy(packet.payload, payload.data(), std::min(sizeof(packet.payload), payload.size()));
    std::string bitstream = twt::serializePacket(packet);

    char bits[BUFFER_SIZE];
    for (int i = 0; i < BUFFER_SIZE; i ++)
        bits[i] = bitstream[i];

    int n;

    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &serv_addr.sin_addr, buffer, sizeof(buffer));

    n = sendto(sockfd, &bits, BUFFER_SIZE, 0, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
    
    if (n < 0) {
        perror("ERROR in sendto");
        std::cerr << "Error code: " << errno << std::endl;
    } 
    // std::cout << "Sent " << n << " bytes to " << buffer << ":" << ntohs(serv_addr.sin_port) << std::endl;
    return n;
}

void Client::processReceiving() {
    while (true) {
        char buffer[BUFFER_SIZE] = {0};
        struct sockaddr_in servaddr;
        socklen_t len;
        int valread;

        len = sizeof(servaddr);
        valread = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&servaddr, &len);
        if(valread == -1) {
            perror("Error receiving data");
            break;
        }

        // Bloqueie o mutex antes de acessar o buffer de recebimento
        std::lock_guard<std::mutex> lock(bufferMutex);

        // Adicione os dados recebidos ao buffer de recebimento
        receivingBuffer.push(buffer);
        //std::cout << "Received: " << buffer << std::endl;

        // Notifique qualquer thread que esteja esperando que o buffer de recebimento esteja cheio
        bufferCondVar.notify_all();

        // Limpe o buffer
        memset(buffer, 0, sizeof(buffer));
    }
}

std::string Client::getBuffer() {
    // Bloqueie o mutex antes de acessar o buffer de recebimento
    std::lock_guard<std::mutex> lock(bufferMutex);

    // Se o buffer de recebimento estiver vazio, retorne uma string vazia
    if(receivingBuffer.empty()) {
        return "";
    }

    // Caso contrário, obtenha a próxima string do buffer de recebimento
    std::string next = receivingBuffer.front();
    receivingBuffer.pop();
    return next;
}
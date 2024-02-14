#include "header/server.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <random>
#include "../common/header/utils.hpp"

std::unordered_map<int, std::vector<sockaddr_in>> connectedUsers; // User ID -> Set of connected sessions
bool isMainServer;
void printConnectedUsers()
{
    std::cout << "Connected Users:\n";

    for (const auto &entry : connectedUsers)
    {
        std::cout << "User ID: " << entry.first << "\n";

        const std::vector<sockaddr_in> &sessions = entry.second;
        std::cout << "  Sessions:\n";

        for (const auto &session : sessions)
        {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(session.sin_addr), ip, INET_ADDRSTRLEN);
            std::cout << "    IP: " << ip << ", Port: " << ntohs(session.sin_port) << "\n";
        }

        std::cout << "\n";
    }
}

void printOtherServers(std::vector<sockaddr_in> otherServers)
{
    std::cout << "Other servers:" << std::endl;
    for (const auto &server : otherServers)
    {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(server.sin_addr), ip, INET_ADDRSTRLEN);
        int port = ntohs(server.sin_port);
        std::cout << "IP: " << ip << ", Porta: " << port << std::endl;
    }
}

UDPServer::UDPServer(int port, int mainServerPort_param, std::string mainServerIP_param, int serverId)
{
    serverSocket = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in addr = this->toSockaddr(port, this->getIPAddress());
    this->serverId = this->calcID(addr);

    if (serverSocket < 0)
    {
        perror("Error creating socket");
        return;
    }

    if (mainServerIP_param == "")
    {
        mainServerIP = "172.0.0.1"; //"172.28.121.208" // RETIRAR ESSA LINHA POSTERIORMENTE
        isMainServer = true;        // RETIRAR ESSA LINHA POSTERIORMENTE
        port = mainServerPort_param;
    }
    else
    {
        isMainServer = false;
        mainServerIP = mainServerIP_param;
    }

    isMainServerUp = true;
    mainServerPort = mainServerPort_param;
    myServerPort = port;
    std::cout << "Porta do servidor: " << port << std::endl;

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port);

    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        perror("Error binding server socket to port");
        return;
    }

    socklen_t addrSize = sizeof(serverAddress);
    getsockname(serverSocket, reinterpret_cast<sockaddr *>(&serverAddress), &addrSize);

    std::cout << "O socket está usando a porta: " << ntohs(serverAddress.sin_port) << std::endl;

    // Inicialize o lastSequenceNumber no construtor
    lastSequenceNumber.clear(); // Certifique-se de limpar qualquer valor anterior
}

UDPServer::UDPServer(int port)
{
    serverSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (serverSocket < 0)
    {
        perror("Error creating socket");
        return;
    }

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port);

    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        perror("Error binding client socket to port");
        return;
    }
    // Inicialize o lastSequenceNumber no construtor
    lastSequenceNumber.clear(); // Certifique-se de limpar qualquer valor anterior
}

UDPServer::~UDPServer()
{
}

void printMenu()
{
    std::cout << BLUE << ">>-- Welcome to Y --<<" << RESET << std::endl
              << std::endl;
    std::cout << RED << "1. " << RESET << "Display User List\n";
    std::cout << RED << "2. " << RESET << "Display Followers List\n";
    std::cout << RED << "3. " << RESET << "Save Database\n";
    std::cout << RED << "4. " << RESET << "Delete Database\n";
    std::cout << RED << "5. " << RESET << "Exit\n";
    std::cout << BLUE << "Choose an option: " << RESET;
}

void UDPServer::start()
{
    std::cout << "Server listening on port " << PORT << "...\n";
    loadDataBase();
    running = true;
    std::thread processRequestsThread(&UDPServer::handlePackets, this);
    std::thread processPacketsThread(&UDPServer::processPacket, this);
    std::thread processMessageThread(&UDPServer::processMessages, this);
    std::thread processLoginThread(&UDPServer::processLogin, this);
    // std::thread processPingThread(&UDPServer::processPing, this);
    // std::thread processPingEraseThread(&UDPServer::processPingErase, this);

    while (running)
    {
        std::string buffer;
        int choice;
        // clearScreen();
        printMenu();
        std::cin >> buffer;
        std::cin.ignore(); // Consume newline character
        choice = atoi(buffer.c_str());

        switch (choice)
        {
        case 1:
        {
            displayUserList();
            pressEnterToContinue();
            break;
        }
        case 2:
        {
            displayFollowersList();
            pressEnterToContinue();
            break;
        }
        case 3:
        {
            saveDataBase();
            std::cout << "Database sucessfully saved!" << std::endl;
            pressEnterToContinue();
            break;
        }
        case 4:
        {
            std::cout << "Enter the passcode:\n";
            std::string passcode;
            std::cin >> passcode;
            if (passcode.compare("taylorswift") == 0)
            {
                system("rm assets/database.txt");
                std::cout << "Database Successfully removed" << std::endl;
            }
            else
            {
                std::cout << "Incorrect Passcode" << std::endl;
            }
            std::cin.ignore();
            pressEnterToContinue();
            break;
        }
        case 5:
        {
            std::cout << "Exiting the application.\n";
            pressEnterToContinue();
            running = false;
            break;
        }
        case 6:
        {
            loadDataBase();
            std::cout << "Database Load successfully" << std::endl;
            pressEnterToContinue();
            break;
        }
        default:
            std::cout << "Invalid choice. Please try again.\n";
            std::cin.ignore();
            pressEnterToContinue();
        }
    }

    processRequestsThread.join();
    processPacketsThread.join();
    processMessageThread.join();
    processLoginThread.join();
}

void UDPServer::handlePackets()
{
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100 milliseconds
    if (setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        perror("Error setting socket options");
    }

    while (running)
    {
        sockaddr_in clientAddress;
        socklen_t clientSize = sizeof(clientAddress);

        char buffer[BUFFER_SIZE] = {0};
        int bytesRead = recvfrom(serverSocket, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&clientAddress, &clientSize);
        if (bytesRead > 0)
        {
            // std::cout << RED << "Received packet from " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) <<  " msg: "<< buffer << std::endl << RESET;
            std::lock_guard<std::mutex> lock(mutexProcBuff);
            processingBuffer.push({clientAddress, buffer});
        }
    }
}

void UDPServer::resetSequenceNumber(const sockaddr_in &clientAddress)
{
    uint32_t ip = clientAddress.sin_addr.s_addr;
    uint16_t port = clientAddress.sin_port;

    auto it = lastSequenceNumber.find(ip);
    if (it != lastSequenceNumber.end())
    {
        auto innerIt = it->second.find(port);
        if (innerIt != it->second.end())
        {
            // Reseta o último número de sequência para 0
            innerIt->second = 0;
        }
    }
    // Se a entrada não existir, não é necessário fazer nada
}

void UDPServer::processPacket()
{
    while (running)
    {
        std::unique_lock<std::mutex> lock(mutexProcBuff);
        if (!processingBuffer.empty())
        {
            std::string returnMessage("unknown type");
            std::pair<const sockaddr_in &, const std::string &> bufferValue = processingBuffer.front();
            const sockaddr_in &clientAddress = bufferValue.first;
            std::string packet = bufferValue.second;
            processingBuffer.pop();

            twt::Packet pack = twt::deserializePacket(packet);

            /*
             * precisa construir uma funcao que verifique se um pacote esta repetido
             * para isso precisa guardar o ultimo numero de pacote recebido
             * e verificar se o pacote recebido nessa execucao eh repetido ou nao
             * para um usuario em especifico
             * e quando ele faz logout deve resetar o ultimo serialize number para 0
             */
            /*
             * inicializar em 0 last sequence number na estrutura do servidor
             */
            // std::unordered_map<std::pair<int, int>, uint16_t> lastSequenceNumber;
            // lastSequenceNumber[{clientAddress.sin_addr.s_addr, clientAddress.sin_port}] = 0 quando fizer logout
            // if (lastSequenceNumber[{clientAddress.sin_addr.s_addr, clientAddress.sin_port}] < pack.sequence_number) entao eh repetido

            bool packetRepead = isPacketRepeated(pack, clientAddress);
            packetBuffer.push_back({pack, clientAddress});
            if (packetBuffer.size() > 1024)
                packetBuffer.pop_front();

            if (!packetRepead)
            {
                switch (pack.type)
                {
                case twt::PacketType::Mensagem:
                {
                    std::pair<int, std::string> payload = twt::deserializeMessagePayload(pack.payload);
                    uint16_t timestamp = pack.timestamp;
                    messageBuffer.push({{usersList.getUsername(payload.first), payload.first}, payload.second, timestamp});
                    returnMessage = "ACK_MSG,Message request received\nSender ID: " + std::to_string(payload.first) + "\nMessage: " + payload.second + "\n";
                    // UDPServer::sendPacketWithRetransmission( clientAddress, returnMessage);

                    sendto(serverSocket, returnMessage.c_str(), BUFFER_SIZE, 0, (struct sockaddr *)&clientAddress, sizeof(clientAddress));
                    break;
                }
                case twt::PacketType::Follow:
                {
                    std::pair<int, std::string> payload = twt::deserializeFollowPayload(pack.payload);
                    int followerId = payload.first;
                    std::string usernameToFollow = payload.second;

                    std::cout << "User " << usersList.getUsername(followerId) << " is trying to follow " << usernameToFollow << std::endl;

                    int follewedId = usersList.getUserId(usernameToFollow);
                    if (follewedId == -1)
                    { // User not found
                        returnMessage = "ACK_FLW,User not found. Unable to follow.\n";
                    }
                    else if (followerId == follewedId)
                    { // User cannot follow himself
                        returnMessage = "ACK_FLW,You cannot follow yourself. Try following someone else.\n";
                    }
                    else if (followers.isFollowing(followerId, follewedId))
                    { // User already following
                        returnMessage = std::string("ACK_FLW,You are already following ") + usernameToFollow + std::string(".\n");
                    }
                    else
                    {
                        followers.follow(followerId, follewedId);
                        usersList.follow(followerId, follewedId);
                        saveDataBase();
                        returnMessage = std::string("ACK_FLW,You are now following ") + usernameToFollow + std::string(".\n");
                    }

                    std::cout << returnMessage << std::endl;
                    // UDPServer::sendPacketWithRetransmission( clientAddress, returnMessage);
                    sendto(serverSocket, returnMessage.c_str(), BUFFER_SIZE, 0, (struct sockaddr *)&clientAddress, sizeof(clientAddress));
                    break;
                }
                case twt::PacketType::Login:
                {
                    std::string username = twt::deserializeLoginPayload(pack.payload);
                    loginBuffer.push({clientAddress, username});
                    break;
                }
                case twt::PacketType::Exit:
                {
                    int accountId = twt::deserializeExitPayload(pack.payload);
                    handleLogout(clientAddress, accountId);
                    returnMessage = "ACK_EXT,Exit request received\nUserId: " + std::to_string(accountId) + "\n";
                    std::cout << returnMessage;
                    // UDPServer::sendPacketWithRetransmission( clientAddress, returnMessage);
                    sendto(serverSocket, returnMessage.c_str(), BUFFER_SIZE, 0, (struct sockaddr *)&clientAddress, sizeof(clientAddress));

                    break;
                }
                }
                lock.unlock();
            }
        }
        else
        {
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

bool UDPServer::isPacketRepeated(const twt::Packet &pack, const sockaddr_in &clientAddress)
{
    uint32_t ip = clientAddress.sin_addr.s_addr;
    uint16_t port = clientAddress.sin_port;
    // Itere sobre o buffer de pacotes
    for (const PacketInfo &storedPackInfo : packetBuffer)
    {
        // Se um pacote no buffer tiver o mesmo IP, porta e número de sequência, retorne true
        if (storedPackInfo.clientAddress.sin_addr.s_addr == ip && storedPackInfo.clientAddress.sin_port == port && storedPackInfo.packet.sequence_number == pack.sequence_number)
        {
            std::cout << "Pacote repetido recebido" << std::endl;
            return true;
        }
    }
    // Se nenhum pacote repetido for encontrado, retorne false
    return false;
}

void UDPServer::handleLogout(const sockaddr_in &clientAddress, int id)
{
    this->usersList.logout(id);

    // Find the connected sessions for the user
    std::vector<sockaddr_in> &sessions = connectedUsers[id];

    // Iterate through the connected sessions and find the one to be removed
    auto pos = std::find_if(sessions.begin(), sessions.end(), [&](const sockaddr_in &session)
                            {
        // Compare relevant fields (IP address and port) individually
        return session.sin_addr.s_addr == clientAddress.sin_addr.s_addr &&
               session.sin_port == clientAddress.sin_port; });

    // Check if the session was found before erasing
    if (pos != sessions.end())
    {
        sessions.erase(pos);
        std::cout << "Closing user session: " << PURPLE << id << RESET << std::endl;
        std::string clientIPAddress = inet_ntoa(clientAddress.sin_addr);
        std::cout << "Endereço IP do cliente: " << PURPLE << clientIPAddress << RESET << std::endl;

        // Reseta o último número de sequência para 0 quando o cliente faz logout
        resetSequenceNumber(clientAddress);
    }
}

void UDPServer::processLogin()
{
    while (running)
    {
        std::lock_guard<std::mutex> lock(mutexLogBuff);
        if (!loginBuffer.empty())
        {
            std::pair<const sockaddr_in &, const std::string &> pkt = loginBuffer.front();
            sockaddr_in clientAddress = pkt.first;
            std::string username = pkt.second;

            int id = usersList.createSession(username);
            std::string replyMessage = std::string("ACK_LOG,") + std::to_string(id) + std::string(",") + username.c_str() + std::string(",");

            if (id != -1)
            {
                saveDataBase();
                connectedUsers[id].push_back(clientAddress);
                replyMessage = replyMessage + std::string(GREEN) + "Usuario @" + username + " conectado com sucesso!" + GREEN;
                // broadcastMessage(id);
            }
            else
            {
                replyMessage = replyMessage + std::string(RED) + "Usuario @" + username + " nao pode se conectar" + RESET;
            }
            std::cout << "sending ack for login: " << username << " id: " << id << std::endl;
            sendto(serverSocket, replyMessage.c_str(), BUFFER_SIZE, 0, (struct sockaddr *)&clientAddress, sizeof(clientAddress));
            // Obter o endereço IP do cliente como uma string
            std::string clientIPAddress = inet_ntoa(clientAddress.sin_addr);
            sendBufferedMessages(id);
            // Imprimir o endereço IP do cliente na tela
            std::cout << "Endereço IP do cliente: " << clientIPAddress << std::endl;
            loginBuffer.pop();
        }
        else
        {
        }
    }
}

void UDPServer::processMessages()
{
    while (running)
    {
        std::unique_lock<std::mutex> lock(mutexMsgBuff);
        if (!messageBuffer.empty())
        {
            twt::Message msg = messageBuffer.front();
            std::unordered_set<int> userFollowers = this->followers.getFollowers(msg.sender.userId);

            for (auto f : userFollowers)
            {
                userMessageBuffer[f].push(msg);
                broadcastMessage(f);
            }
            messageBuffer.pop();
            lock.unlock();
        }
        else
        {
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void UDPServer::sendBufferedMessages(int userId)
{
    auto it = msgToSendBuffer.begin();
    while (it != msgToSendBuffer.end())
    {
        if (it->first == userId)
        {
            while (!it->second.empty())
            {
                twt::Message message = it->second.front();
                for (const sockaddr_in &userAddr : connectedUsers[userId])
                {
                    std::cout << "\n> Sending message: \"" << message.content.c_str() << "\" to user @" << usersList.getUsername(userId) << "(id " << std::to_string(userId) << ")"
                              << "With port " << userAddr.sin_port << " from user @" << message.sender.username << " (id " << message.sender.userId << ")" << std::endl;
                    std::string str(
                        std::to_string(message.timestamp) + ',' +
                        message.sender.username + ',' +
                        std::to_string(message.sender.userId) + ',' +
                        message.content);
                    sendto(serverSocket, str.c_str(), str.length(), 0, (struct sockaddr *)&userAddr, sizeof(userAddr));
                    // UDPServer::sendPacketWithRetransmission(userAddr, str);
                }
                it->second.pop();
            }
            it = msgToSendBuffer.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void UDPServer::broadcastMessage(int receiverId)
{
    while (!userMessageBuffer[receiverId].empty())
    {
        twt::Message message = userMessageBuffer[receiverId].front();
        if (UserConnected(receiverId))
        {
            for (const sockaddr_in &userAddr : connectedUsers[receiverId])
            {
                std::cout << "\n> Sending message: \"" << message.content.c_str() << "\" to user @" << usersList.getUsername(receiverId) << "(id " << std::to_string(receiverId) << ")"
                          << " from user @" << message.sender.username << " (id " << message.sender.userId << ")" << std::endl;
                std::string str(
                    std::to_string(message.timestamp) + ',' +
                    message.sender.username + ',' +
                    std::to_string(message.sender.userId) + ',' +
                    message.content);
                sendto(serverSocket, str.c_str(), str.length(), 0, (struct sockaddr *)&userAddr, sizeof(userAddr));
                // UDPServer::sendPacketWithRetransmission(userAddr, str);
            }
        }
        else
        {
            // Se o usuário não estiver conectado, salve o userId e o message.sender.username em msgToSendBuffer
            std::cout << "User " << usersList.getUsername(receiverId) << " is not connected. Saving message in buffer." << std::endl;
            msgToSendBuffer[receiverId].push(message);
        }
        userMessageBuffer[receiverId].pop();
    }
}

bool UDPServer::UserConnected(int userId)
{
    // Verifique se o userId existe em connectedUsers
    if (connectedUsers.find(userId) != connectedUsers.end())
    {
        // Se existir, verifique se há pelo menos um usuário conectado
        if (!connectedUsers[userId].empty())
        {
            return true;
        }
    }
    // Se o userId não existir em connectedUsers ou não houver usuários conectados, retorne false
    return false;
}

std::unordered_map<int, twt::UserInfo> UDPServer::getUsersList()
{
    return this->usersList.getUserListInfo();
}

void UDPServer::displayUserList()
{
    std::cout << "User List:\n";
    for (auto user : this->getUsersList())
        user.second.display();
}

void UDPServer::displayFollowersList()
{
    std::unordered_map<int, twt::UserInfo> allUsers = this->getUsersList();
    for (auto user : allUsers)
    {
        std::unordered_set<int> followList = followers.getFollowers(user.first);
        if (followList.empty())
        {
            std::cout << "User \033[1;33m" << usersList.getUsername(user.first) << "\033[0m has no followers\n";
        }
        else
        {
            std::cout << "User \033[1;33m" << usersList.getUsername(user.first) << "\033[0m followers: ";
            for (int follower : followList)
                std::cout << "\033[1;32m" << usersList.getUsername(follower) << " (" << std::to_string(follower) << ") ";
            std::cout << "\033[0m" << std::endl;
        }
    }
}

void UDPServer::saveDataBase()
{
    std::vector<twt::UserInfo> users_vector;
    loadFollowersIntoUsersList();
    users_vector = usersList.storageMap();
    // Para cada userId na usersList

    /*for (auto user : users_vector){
        std::cout << "User ID: " << RED << user.getId() << RESET << ", Username: " << RED << user.getUsername() << RESET << std::endl;
        std::cout << "Followers: " << std::endl;
        for (auto followerId : user.getFollowers())
            std::cout << '\t' << PURPLE << followerId << RESET << ": " << BLUE << usersList.getUsername(followerId) << std::endl;
        std::cout << std::endl;
    }
    */
    write_file(DATABASE_NAME, users_vector);
}

void UDPServer::loadDataBase()
{
    std::vector<twt::UserInfo> users_vector;
    users_vector = read_file(DATABASE_NAME);
    usersList.loadMap(users_vector);
    saveFollowersFromUsersList();
    usersList.setNextId(findMaxUserId(users_vector) + 1);
}

void UDPServer::loadFollowersIntoUsersList()
{
    // Para cada userId na usersList
    for (int userId : usersList.getUserIds())
    {
        // Obter os seguidores do userId
        std::unordered_set<int> followerIds = followers.getFollowers(userId);

        // Para cada seguidor, adicione-o à lista de seguidores do usuário correspondente na usersList
        for (int followerId : followerIds)
        {
            twt::UserInfo &userInfo = usersList.getUser(followerId);
            userInfo.getFollowers().insert(userId);
        }
    }
}

void UDPServer::saveFollowersFromUsersList()
{
    // Para cada userId na usersList
    for (int userId : usersList.getUserIds())
    {
        // Obter o UserInfo para o userId
        twt::UserInfo &userInfo = usersList.getUser(userId);

        // Para cada seguidor do usuário, adicione-o à lista de seguidores
        for (int followerId : userInfo.getFollowers())
        {
            followers.follow(followerId, userId);
        }
    }
}

bool UDPServer::waitForAck()
{
    auto start = std::chrono::high_resolution_clock::now();

    while (true)
    {
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;

        // Se passaram mais de 3 segundos
        if (elapsed.count() > 0.3)
        {
            std::cout << "Ack não recebido, retransmitindo..." << std::endl;
            return false;
        }

        // Verificar se o ACK foi recebido
        if (isAckReceived)
        {
            std::cout << "Ack recebido com sucesso." << std::endl;
            isAckReceived = false;
            return true;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
void UDPServer::sendPacketWithRetransmission(const sockaddr_in &clientAddress, std::string returnMessage)
{
    // uint16_t timestamp = getTimeStamp();
    int retransmitAttempts = 0, n, nacks = 0;

    while (retransmitAttempts < 3 && nacks < 3)
    {
        // Incrementa o número de tentativas de retransmissão
        retransmitAttempts++;
        // Envie o pacote
        n = sendto(serverSocket, returnMessage.c_str(), BUFFER_SIZE, 0, (struct sockaddr *)&clientAddress, sizeof(clientAddress));

        // Verifique se o ACK foi recebido dentro do tempo limite
        if (waitForAck())
        {
            nacks++;
        }
        else
            break;
        if (n < 0)
        {
            perror("ERROR in sendto");
            std::cerr << "Error code: " << errno << std::endl;
        }
    }

    if (nacks == 3)
        std::cout << "Não foi possível se conectar ao cliente, tente novamente dentro de alguns instantes" << RED << RESET << std::endl;
}

void UDPServer::start_replication()
{
    running = true;
    std::cout << "Server Replication listening on port " << myServerPort << "...\n";
    std::thread PingThread(&UDPServer::Ping, this);
    std::thread ReceiveThread(&UDPServer::handlePackets, this); // ????
    std::thread ConsumeBufferThread(&UDPServer::processPacket_server, this);
    std::thread sendBackupPacketThread(&UDPServer::sendBackupPacket, this);
    std::thread anounceMainServerThread(&UDPServer::anounceMainServer, this);
    // std::thread sendPacketThread(&UDPServer::sendPacket, this);

    while (running)
    {
    }

    sendBackupPacketThread.join();
    anounceMainServerThread.join();
    PingThread.join();
    ReceiveThread.join();
    ConsumeBufferThread.join();
}

void UDPServer::anounceMainServer()
{
    while (running)
    {
        if (isMainServer)
        {
            // printConnectedUsers();
            std::string message = "Main," + mainServerIP + "," + std::to_string(PORT);
            // Send message to all connected users
            for (const auto &entry : connectedUsers)
            {
                int userID = entry.first;
                for (const sockaddr_in &userAddr : connectedUsers[userID])
                {
                    // std::cout << "Anouncing main server to: " << inet_ntoa(userAddr.sin_addr) << ":" << ntohs(userAddr.sin_port) << std::endl;
                    //  CHANGED:
                    //  sendto(serverSocket, message.c_str(), message.size(), 0, (struct sockaddr *)&userAddr, sizeof(userAddr));
                    sendto(serverSocket, message.c_str(), BUFFER_SIZE, 0, (struct sockaddr *)&userAddr, sizeof(userAddr));
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
}

void UDPServer::Ping()
{
    while (running)
    {
        if (!isMainServer)
        {
            int maxAttempts = 500;
            sockaddr_in receivedPing;
            struct sockaddr_in mainServerAddress;
            memset(&mainServerAddress, 0, sizeof(mainServerAddress));
            mainServerAddress.sin_family = AF_INET;
            mainServerAddress.sin_port = htons(mainServerPort);
            inet_pton(AF_INET, mainServerIP.c_str(), &(mainServerAddress.sin_addr));
            for (int attempt = 0; attempt < maxAttempts; ++attempt)
            {
                // std::cout << "Sending ping message to: " << inet_ntoa(mainServerAddress.sin_addr) << ":" << ntohs(mainServerAddress.sin_port) << std::endl;
                //  std::cout << "Sending ping message to: " << inet_ntoa(mainServerAddress.sin_addr) << ":" << ntohs(mainServerAddress.sin_port) << std::endl;
                sendto(serverSocket, "Ping", BUFFER_SIZE, 0, (struct sockaddr *)&mainServerAddress, sizeof(mainServerAddress));
                // std::cout << "Sent ping message to: " << inet_ntoa(mainServerAddress.sin_addr) << ":" << ntohs(mainServerAddress.sin_port) << std::endl;
                auto startTime = std::chrono::steady_clock::now();
                const auto waitDuration = std::chrono::milliseconds(1);
                while (std::chrono::steady_clock::now() - startTime < waitDuration)
                {
                    // Wait for the specified duration
                }
                // std::cout << "Waited for reply ping message from: " << inet_ntoa(mainServerAddress.sin_addr) << ":" << ntohs(mainServerAddress.sin_port) << std::endl;
                if (!pingQueue.empty())
                {
                    receivedPing = pingQueue.front();
                    pingQueue.pop();
                    if (receivedPing.sin_port == mainServerAddress.sin_port && receivedPing.sin_addr.s_addr == mainServerAddress.sin_addr.s_addr)
                    {
                        isMainServerUp = true;
                        // std::cout << "Main server is up" << std::endl;
                        break;
                    }
                }
                // std::cout << BLUE << "Tentativa numero: " << attempt+1 <<std::endl;
                if (attempt == maxAttempts - 1)
                {
                    isMainServerUp = false;
                    std::cout << "Main server is down" << std::endl;
                    electionMainServer();
                }
            }
        }
    }
}

void UDPServer::processPingMessage(sockaddr_in clientAddress)
{
    // std::lock_guard<std::mutex> lock(mutexServerSend);
    // sendBuffer.push({clientAddress, "Reply Ping"});
    // std::cout << "Sending reply to: " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << std::endl;
    sendto(serverSocket, "Reply Ping", BUFFER_SIZE, 0, (struct sockaddr *)&clientAddress, sizeof(clientAddress));
    bool alreadyIn = false;
    for (auto &server : otherServers)
    {
        if (inet_ntoa(server.sin_addr) == inet_ntoa(clientAddress.sin_addr) && server.sin_port == clientAddress.sin_port)
        {
            alreadyIn = true;
        }
    }
    if (!alreadyIn)
    {
        // std::cout << "Adding server to list: " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << std::endl;
        otherServers.push_back(clientAddress);
    }
    // printOtherServers(otherServers);
}

void UDPServer::processPacket_server()
{
    while (running)
    {
        std::unique_lock<std::mutex> lock(mutexProcBuff);
        if (!processingBuffer.empty())
        {
            std::string returnMessage("unknown type");
            std::pair<const sockaddr_in &, const std::string &> bufferValue = processingBuffer.front();
            const sockaddr_in &clientAddress = bufferValue.first;
            std::string packet = bufferValue.second;
            processingBuffer.pop();

            if (packet.find("Backup") != std::string::npos && !isMainServer)
            {
                // std::cout << "Recived Backup packet from " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << std::endl;
                processBackup(packet);
            }
            else if (packet == "Ping")
            {
                processPingMessage(clientAddress);
            }
            else if (packet == "Reply Ping")
            {
                // std::cout << "Received Reply Ping packet from " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << std::endl;
                pingQueue.push(clientAddress);
            }
            else if (packet.find("Election Result"))
            {
                // processElectionResult(packet);
                std::cout << "Received Election result from " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << std::endl;
            }
            else if (packet.find("Request Elect"))
            {
                // retorna id LUIS ENTRA NO DISCORD!!!!
                // std::cout << std::endl << "received Election Request--------" << std::endl;
                std::string toSend = std::string("Election Request Ack;") + this->getIPAddress() + std::string(";") + std::to_string(this->myServerPort) + std::string(";");
                // std::cout << std::endl << "received Election Request..." << std::endl;
                std::cout << "Received Election request from " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << std::endl;
                std::cout << "sending back ack..." << std::endl;
                sendto(serverSocket, toSend.c_str(), BUFFER_SIZE, 0, (struct sockaddr *)&clientAddress, sizeof(clientAddress));
            }
            else if (packet.find("Election Request Ack"))
            {
                std::cout << std::endl
                          << "RECEIVED ACK" << std::endl;
                std::cout << "Received Election request ack from " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << std::endl;
                processElectionRequestAck(packet, clientAddress);
            }
        }
        else
        {
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

// "Election Result" + ";" + "<MainServer port>" + ";" + "<Main Server IP"
void UDPServer::processElectionResult(const std::string &packet)
{
    std::vector<std::string> result = splitString(packet);
    if (result.size() < 2)
        return;
    int electionServerPort = atoi(result[2].c_str());
    std::string electionServerIp = result[1];
    sockaddr_in electionServerAddr = this->toSockaddr(electionServerPort, electionServerIp);
    // std::cout << "election server port: " << electionServerPort << std::endl;
    // std::cout << "election server ip: " << electionServerIp << std::endl;
    std::string electionServerId = this->calcID(electionServerAddr);

    mainServerPort = electionServerPort;
    mainServerIP = electionServerIp;
    std::cout << "Election ID: " << electionServerId << std::endl
              << "Server ID: " << this->serverId << std::endl;
    if (electionServerId == this->serverId)
    {
        isMainServer = true;
        std::cout << "became main server through other\'s election" << std::endl;
    }
}

std::string UDPServer::calcID(sockaddr_in Address)
{
    std::string id = inet_ntoa(Address.sin_addr);
    id += ":";
    id += std::to_string(ntohs(Address.sin_port));
    return id;
}

void UDPServer::processElectionRequestAck(const std::string &packet, const sockaddr_in &clientaddr)
{
    // TODO: verify if the ack received is greater than the greatest id received until then
    // update greatestResponseId and greatestResponsePort
    // if (calcId(a) > calcId(b))

    // separação do ip e porta do pacote recebido
    std::cout << "packet : " << packet << std::endl;
    std::vector<std::string> tokens = splitString(packet);
    if (tokens.size() < 2)
        return;
    std::string receivedIp = tokens[1];
    int receivedPort = atoi(tokens[2].c_str());

    sockaddr_in address = toSockaddr(receivedPort, receivedIp);
    sockaddr_in current_addr = toSockaddr(myServerPort, getIPAddress());

    std::string senderId = calcID(address);
    std::string currentId = calcID(current_addr);

    // Verificando se o ID do remetente é maior que o ID atual do servidor
    if (senderId > currentId)
    {
        // Atualizando o maior ID recebido e a porta correspondente
        greatestResponseIp = receivedIp;
        greatestResponsePort = receivedPort;
    }
}

sockaddr_in UDPServer::toSockaddr(int port, std::string ip)
{
    sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &(address.sin_addr));
    return address;
}

void UDPServer::removeHighestIdServer(std::vector<sockaddr_in> &otherServers)
{
    int highestId = 0;
    auto highestIdIter = otherServers.end(); // Iterator pointing to the highest ID server
    for (auto iter = otherServers.begin(); iter != otherServers.end(); ++iter)
    {
        int id = hashIPPort(calcID(*iter));
        if (id > highestId)
        {
            highestId = id;
            highestIdIter = iter;
        }
    }

    if (highestIdIter != otherServers.end())
    {
        otherServers.erase(highestIdIter); // Remove the highest ID server
    }
}

// Função para obter os IDs mais altos do vetor de servidores
std::vector<std::pair<std::string, int>> UDPServer::getHigherIds(std::vector<sockaddr_in> &otherServers, std::string cmp_id)
{
    std::vector<std::pair<std::string, int>> higherIds;

    int cmp_id_int = hashIPPort(cmp_id);
    int id_int;

    std::cout << cmp_id << std::endl;
    // Adiciona os servidores com IDs maiores ao vetor de IDs mais altos
    for (auto &server : otherServers)
    {
        std::string id = calcID(server);
        //std::cout << inet_ntoa(server.sin_addr) << ":" << ntohs(server.sin_port) << std::endl;

        id_int = hashIPPort(id);

        if (id_int > cmp_id_int)
        {
            std::string ip = inet_ntoa(server.sin_addr);
            int port = ntohs(server.sin_port);
            higherIds.push_back(std::make_pair(ip, port));
        }
    }

    /// FUNÇÂO A SER MOVIDA DE LUGAR

    int highestId = 0;
    int i = 0;
    sockaddr_in highestIdServer;
    std::vector<sockaddr_in> copiedServers;
    for (auto &server : otherServers)
    {
        int id = hashIPPort(calcID(server));
        if (i==0) 
            highestId = id-1;
        int port = ntohs(server.sin_port);
        std::string ip = inet_ntoa(server.sin_addr);
        if (id > highestId)
        {
            mainServerPort = port;
            mainServerIP = ip;
            highestIdServer = server;
        }
        i++;
    }
    for (auto &server : otherServers)
    {
        
        if (!(inet_ntoa(server.sin_addr) == inet_ntoa(highestIdServer.sin_addr) && server.sin_port == highestIdServer.sin_port))
        {
            copiedServers.push_back(server);
        }
        else
        {
            std::cout << "Achou o main" << std::endl;
        }
    }
    otherServers = copiedServers;

    std::cout << BLUE << "main port:" << mainServerPort << std::endl;
    std::cout << GREEN << "main ip:" << mainServerIP << std::endl;
    /// FUNÇÂO A SER MOVIDA DE LUGAR

    return higherIds;
}

void UDPServer::processBackup(const std::string &packet)
{
    std::istringstream iss(packet);
    std::string token;

    // 1st part: Just the word Backup
    std::getline(iss, token, '/');

    // 2nd part: Vector of pairs (string, int)
    std::getline(iss, token, '/');
    std::istringstream pairStream(token);
    std::string ip;
    int port;
    std::vector<sockaddr_in> otherServersTemp;
    while (std::getline(pairStream, token, ';'))
    {
        std::istringstream pair(token);
        std::getline(pair, ip, ',');
        std::getline(pair, token, ',');
        std::istringstream(token) >> port;
        // std::cout << "2nd: (" << ip << ", " << port << ")" << std::endl;
        sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &(address.sin_addr));
        otherServersTemp.push_back(address);
    }

    /*for (const std::string &pair : ipPortPairs)
    {
        size_t commaPos = pair.find(',');
        if (commaPos != std::string::npos)
        {
            std::string ip = pair.substr(0, commaPos);
            std::string portStr = pair.substr(commaPos + 1);

            // Converter a string do port para inteiro
            int port = std::stoi(portStr);

            // Configurar a estrutura sockaddr_in
            sockaddr_in address;
            memset(&address, 0, sizeof(address));
            address.sin_family = AF_INET;
            address.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &(address.sin_addr));

            // Adicionar ao vetor
            otherServers.push_back(address);
        }
    }

    // Exemplo de como acessar os elementos do vetor de sockaddr_in
    std::cout << "2nd: Other servers:" << std::endl;
    for (const sockaddr_in &addr : otherServers)
    {
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr.sin_addr), ipStr, INET_ADDRSTRLEN);
        std::cout << "IP: " << ipStr << ", Port: " << ntohs(addr.sin_port) << std::endl;
    }*/

    // 3rd part: Queue with (uint16, int, string)
    std::getline(iss, token, '/');
    std::istringstream queueStream(token);
    std::queue<twt::Message> messageBufferTemp;
    while (std::getline(queueStream, token, ';'))
    {
        uint16_t param1;
        int param2;
        std::string param3;
        std::string param4;
        twt::Message tempMessage;
        twt::User tempUser;
        std::istringstream tupleStream(token);
        std::getline(tupleStream, token, ',');
        std::istringstream(token) >> param1;
        std::getline(tupleStream, token, ',');
        std::istringstream(token) >> param2;
        std::getline(tupleStream, token, ',');
        std::istringstream(token) >> param3;
        std::getline(tupleStream, param4, ',');
        tempUser.userId = param2;
        tempUser.username = param3;
        tempMessage.timestamp = param1;
        tempMessage.sender = tempUser;
        tempMessage.content = param4;
        messageBufferTemp.push(tempMessage);
        // std::cout << "3rd: (" << param1 << ", " << param2 << ", " << param3 << ", "<< param4 <<")" << std::endl;
        // queue.push(std::make_tuple(param1, param2, param3));
    }
    // std::cout << "3rd: Queue Size: " << queue.size() << std::endl;

    std::getline(iss, token, '/');
    std::istringstream dbStream(token);
    std::vector<twt::UserInfo> userVectorTemp;
    while (std::getline(dbStream, token, ':'))
    {
        twt::UserInfo tempUser;
        std::unordered_set<int> tempFollowers;
        std::string tempName;
        int tempId;
        std::istringstream entryStream(token);

        std::getline(entryStream, tempName, ';');

        std::getline(entryStream, token, ';');
        std::istringstream numbersStream(token);
        while (std::getline(numbersStream, token, ','))
        {
            int num;
            std::istringstream(token) >> num;
            tempFollowers.insert(num);
        }

        std::getline(entryStream, token, ',');
        tempId = std::stoi(token);

        tempUser.user.username = tempName;
        tempUser.user.userId = tempId;
        tempUser.followers = tempFollowers;
        /*std::cout << "Name: " << tempName << " Followers: ";
        for(int i : tempFollowers)
            std::cout << " " << i;
        std::cout << " UserID: " << tempId << std::endl;*/
        userVectorTemp.push_back(tempUser);
    }

    otherServers = otherServersTemp;
    messageBuffer = messageBufferTemp;
    write_file(DATABASE_NAME, userVectorTemp);
    /*for (const sockaddr_in &addr : otherServersTemp)
    {
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr.sin_addr), ipStr, INET_ADDRSTRLEN);
        std::cout << "IP: " << ipStr << ", Port: " << ntohs(addr.sin_port) << std::endl;
    }

    std::queue<twt::Message> tempMessageBufferTemp = messageBufferTemp;
    while (!tempMessageBufferTemp.empty())
    {
        twt::Message message = tempMessageBufferTemp.front();
        std::cout << "Timestamp: " << message.timestamp << " Sender: " << message.sender.userId << " " << message.sender.username << " Content: " << message.content << std::endl;
        tempMessageBufferTemp.pop();
    }

    for(const twt::UserInfo &user : userVectorTemp)
    {
        std::cout << "Name: " << user.user.username << " Followers: ";
        for(int i : user.followers)
            std::cout << " " << i;
        std::cout << " UserID: " << user.user.userId << std::endl;
    }*/
}

void UDPServer::startElection(std::vector<std::pair<std::string, int>> serversToSend)
{
    std::pair<int, std::string> result;
    std::string toSend("Request Elect " + this->serverId + ";");
    std::cout << PURPLE << "ta començando a eleição" << std::endl;
    this->greatestResponsePort = myServerPort;
    this->greatestResponseIp = getIPAddress();

    std::cout << "servers to send: " << serversToSend.size() << std::endl;
    for (auto server : serversToSend)
    {
        sockaddr_in address = toSockaddr(server.second, server.first);

        if ((server.first != getIPAddress() &&
             server.first != "127.0.0.1") ||
            server.second != myServerPort)
        {
            std::cout << GREEN << "Sending election request to: " << inet_ntoa(address.sin_addr) << ":" << ntohs(address.sin_port) << std::endl
                      << RESET;
            sendto(this->serverSocket, toSend.c_str(), BUFFER_SIZE, 0, (struct sockaddr *)&address, sizeof(address));
        }
    }
    return;
}

void UDPServer::sendElectionResult(int port, std::string ip)
{
    std::string toSend("Election Result;" + std::to_string(port) + ';' + ip + ';');
    for (auto server : otherServers)
    {
        if (calcID(server) != this->serverId)
            sendto(this->serverSocket, toSend.c_str(), BUFFER_SIZE, 0, (struct sockaddr *)&server, sizeof(server));
    }
}

void UDPServer::electionMainServer()
{
    // isMainServer = true;
    // mainServerPort = myServerPort;
    // mainServerIP = getIPAddress();
    std::pair<int, std::string> elect;

    std::cout << "chega aqui" << std::endl;
    // printOtherServers(otherServers);
    //       TODO: returns a vector of that contains the address of the server with higher ID than the current server
    auto ip = this->getIPAddress();
    std::cout << "ip: " << ip << std::endl;
    auto addr = this->toSockaddr(this->myServerPort, ip);
    
    this->greatestResponsePort = myServerPort;
    this->greatestResponseIp = getIPAddress();

    auto other_server_addr = getHigherIds(otherServers, this->calcID(addr));

    //      TODO: create a function that sends a message to all server with ID higher than this->serverId

    // startElection(other_server_addr);
    std::cout << "Saiu do start election" << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    if (mainServerIP == getIPAddress() && mainServerPort == myServerPort)
    {
        isMainServer = true;
        std::cout << "became main server through its own election" << std::endl;
        // sendElectionResult(mainServerPort, mainServerIP);
    }
    else
    {
        std::cout << "Elected" << mainServerIP << ":" << mainServerPort << std::endl;
        isMainServer = false;
    }
    printOtherServers(otherServers);
    //      TODO: create a function that sends the winner of the election to all of the servers active
}

void UDPServer::sendBackupPacket()
{
    while (running)
    {
        if (isMainServer == true)
        {
            for (const auto &server : otherServers)
            {
                // std::lock_guard<std::mutex> lock(mutexServerSend);
                const std::string serverIp = inet_ntoa(server.sin_addr);
                // const int serverPort = ntohs(server.sin_port);
                //  sendBuffer.push({server, "Backup"});
                auto temp = serializeDatabase();
                std::string toSend;
                while (!temp.empty())
                {
                    toSend = toSend + temp.front();
                    temp.pop();
                }
                sendto(serverSocket, toSend.c_str(), BUFFER_SIZE, 0, (struct sockaddr *)&server, sizeof(server));
            }
            // auto temp = serializeDatabase();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    }
}

std::queue<std::string> UDPServer::serializeDatabase()
{
    std::queue<std::string> serializedDatabase;
    serializedDatabase.push("Backup/");
    // std::cout << "Serializing otherServers" << std::endl;
    // printOtherServers(otherServers);
    for (sockaddr_in &server : otherServers)
    {
        std::string serverIp = inet_ntoa(server.sin_addr);
        std::string serverPort = std::to_string(ntohs(server.sin_port));
        std::string serializedData = serverIp + "," + serverPort;
        if (&server != &otherServers.back())
        {
            serializedData = serializedData + ";";
        }
        serializedDatabase.push(serializedData);
    }

    serializedDatabase.push("/");
    std::queue<twt::Message> tempMessageBuffer = messageBuffer;
    while (!tempMessageBuffer.empty())
    {
        twt::Message message = tempMessageBuffer.front();
        std::string serializedData = std::to_string(message.timestamp) + "," + std::to_string(message.sender.userId) + "," + message.sender.username + "," + message.content;
        tempMessageBuffer.pop();
        if (!tempMessageBuffer.empty())
        {
            serializedData = serializedData + ";";
        }
        serializedDatabase.push(serializedData);
    }
    serializedDatabase.push("/");
    std::vector<twt::UserInfo> tempVec = read_file(DATABASE_NAME);
    for (twt::UserInfo &user : tempVec)
    {
        std::string serializeData = format_data(user);
        if (&user != &tempVec.back())
        {
            serializeData = serializeData + ":";
        }
        serializedDatabase.push(serializeData);

        // std::cout << serializeData;
    }

    /*while (!serializedDatabase.empty())
    {
        std::cout << serializedDatabase.front() << std::endl;
        serializedDatabase.pop();
    }*/
    return serializedDatabase;
}

int generateRandomNumber()
{
    // Use um motor de números aleatórios e uma distribuição uniforme
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distribution(10000, 30000);

    // Gere e retorne o número aleatório
    return distribution(gen);
}

std::string UDPServer::getIPAddress()
{
    struct ifaddrs *ifAddrStruct = nullptr;
    void *tmpAddrPtr = nullptr;
    std::string ipAddress;

    // Obter a lista de todas as interfaces de rede
    if (getifaddrs(&ifAddrStruct) == -1)
    {
        std::cerr << "Erro ao obter informações das interfaces de rede\n";
        return "";
    }

    // Percorrer as interfaces de rede
    for (struct ifaddrs *ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == nullptr)
            continue;

        // Ignorar interfaces que não são do tipo AF_INET (IPv4)
        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            // Obter o endereço IP como uma string
            tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            std::string interfaceName(ifa->ifa_name);

            // Considerar apenas interfaces não loopback
            if (interfaceName != "lo")
            {
                ipAddress = std::string(addressBuffer);
                break;
            }
        }
    }

    // Liberar a memória alocada para a lista de interfaces de rede
    if (ifAddrStruct != nullptr)
        freeifaddrs(ifAddrStruct);

    return ipAddress;
}

int main(int argc, char *argv[])
{
    int porta_main, port_server_replica;
    bool initialized = false, running = true;
    std::string ip;
    port_server_replica = generateRandomNumber();
    if (argc < 3)
    {
        std::cerr << "Uso: " << argv[0] << " [porta] [IP]\n";
        ip = "";
    }
    else
    {
        ip = argv[2];
    }
    porta_main = std::stoi(argv[1]);

    UDPServer serverServer(port_server_replica, porta_main, ip, 0);

    std::thread serverThread(&UDPServer::start_replication, &serverServer);
    std::thread clientThread;
    while (running)
    {

        if (isMainServer && !initialized)
        {
            initialized = true;
            UDPServer clientServer(PORT);
            clientThread = std::thread(&UDPServer::start, &clientServer);
        }
    }

    serverThread.join();
    clientThread.join();

    return 0;
}
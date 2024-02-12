#include "header/server.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <random>
#include "../common/header/utils.hpp"

UDPServer::UDPServer(int port, int mainServerPort_param, std::string mainServerIP_param)
{
    serverSocket = socket(AF_INET, SOCK_DGRAM, 0);

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
        clearScreen();
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
            std::lock_guard<std::mutex> lock(mutexProcBuff);
            processingBuffer.push({clientAddress, buffer});
            // std::cout << "Received packet from " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) <<  " msg: "<< buffer << std::endl;
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
    std::vector<sockaddr_in> &sessions = this->connectedUsers[id];

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
                              << " from user @" << message.sender.username << " (id " << message.sender.userId << ")" << std::endl;
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
    write_file(database_name, users_vector);
}

void UDPServer::loadDataBase()
{
    std::vector<twt::UserInfo> users_vector;
    users_vector = read_file(database_name);
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
    std::thread ReceiveThread(&UDPServer::handlePackets, this);
    std::thread ConsumeBufferThread(&UDPServer::processPacket_server, this);
    std::thread sendBackupPacketThread(&UDPServer::sendBackupPacket, this);
    // std::thread sendPacketThread(&UDPServer::sendPacket, this);

    while (running)
    {
    }

    sendBackupPacketThread.join();
    PingThread.join();
    ReceiveThread.join();
    ConsumeBufferThread.join();
}

void UDPServer::Ping()
{
    while (running)
    {
        if (!isMainServer)
        {
            sockaddr_in receivedPing;
            struct sockaddr_in mainServerAddress;
            memset(&mainServerAddress, 0, sizeof(mainServerAddress));
            mainServerAddress.sin_family = AF_INET;
            mainServerAddress.sin_port = htons(mainServerPort);
            inet_pton(AF_INET, mainServerIP.c_str(), &(mainServerAddress.sin_addr));
            for (int attempt = 0; attempt < 5; ++attempt)
            {
                std::cout << "Sending ping message to: " << inet_ntoa(mainServerAddress.sin_addr) << ":" << ntohs(mainServerAddress.sin_port) << std::endl;
                // std::cout << "Sending ping message to: " << inet_ntoa(mainServerAddress.sin_addr) << ":" << ntohs(mainServerAddress.sin_port) << std::endl;
                sendto(serverSocket, "Ping", BUFFER_SIZE, 0, (struct sockaddr *)&mainServerAddress, sizeof(mainServerAddress));

                // Aguarde a resposta por 1 ms
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                if (!pingQueue.empty())
                {
                    receivedPing = pingQueue.front();
                    pingQueue.pop();
                    if (receivedPing.sin_port == mainServerAddress.sin_port)
                    {
                        isMainServerUp = true;
                        std::cout << "Main server is up" << std::endl;
                        break;
                    }
                }

                if (attempt == 4)
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
        otherServers.push_back(clientAddress);
    }
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
            std::cout << "Received packet from " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << " msg: " << packet << std::endl;

            if (packet.find("Backup") != std::string::npos)
            {
                std::cout << "Recived Backup packet from " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << std::endl;
                processBackup(packet);
            }
            else if (packet == "Ping")
            {
                processPingMessage(clientAddress);
            }
            else if (packet == "Reply Ping")
            {
                std::cout << "Received Reply Ping packet from " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << std::endl;
                pingQueue.push(clientAddress);
            }
        }
        else
        {
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void UDPServer::processBackup(const std::string& packet){
    std::istringstream iss(packet);
    std::string token;

    // 1st part: Just the word Backup
    std::getline(iss, token, '/');
    std::cout << "1st: " << token << std::endl;

    // 2nd part: Vector of pairs (string, int)
    std::getline(iss, token, '/');
    std::istringstream pairStream(token);
    std::string name;
    int number;
    while (std::getline(pairStream, name, ',')) {
        std::getline(pairStream, token, ',');
        std::istringstream(token) >> number;
        std::cout << "2nd: (" << name << ", " << number << ")" << std::endl;
    }

    // 3rd part: Queue with (uint16, int, string)
    std::getline(iss, token, '/');
    std::istringstream queueStream(token);
    std::queue<twt::Message> queue;
    while (std::getline(queueStream, token, ',')) {
        uint16_t param1;
        int param2;
        std::string param3;
        std::string param4;
        twt::Message messageTemp;
        twt::User userTemp;
        std::istringstream(token) >> param1;
        std::getline(queueStream, token, ',');
        std::istringstream(token) >> param2;
        std::getline(queueStream, param3, ',');
        std::istringstream(token) >> param3;
        std::getline(queueStream, param4, ',');
        userTemp.userId = param2;
        userTemp.username = param3;
        messageTemp.sender = userTemp;
        messageTemp.timestamp = param1;
        messageTemp.content = param4;
        queue.push(messageTemp);
        std::cout << "3rd: (" << param1 << ", " << param2 << ", " << param3 <<  ", " << param4 << ")" << std::endl;
    }
    std::cout << "3rd: Queue Size: " << queue.size() << std::endl;

    // 4th part: Database with struct
    /*std::getline(iss, token, '/');
    std::istringstream dbStream(token);
    std::vector<DatabaseEntry> database;
    while (std::getline(dbStream, token, ';')) {
        DatabaseEntry entry;
        entry.name = token;

        std::getline(dbStream, token, ';');
        std::istringstream numbersStream(token);
        while (std::getline(numbersStream, token, ',')) {
            int num;
            std::istringstream(token) >> num;
            entry.numbers.push_back(num);
        }

        std::getline(dbStream, token, ',');
        std::istringstream(token) >> entry.singleNumber;

        database.push_back(entry);
    }
    std::cout << "4th: Database Size: " << database.size() << std::endl;*/
}


void UDPServer::electionMainServer()
{
    std::cout << "Starting election" << std::endl;
    mainServerPort = 4002;
    mainServerIP = "127.0.0.1";
    std::cout << "New Main Server Elected" << std::endl;
    return;
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
                const int serverPort = ntohs(server.sin_port);
                // sendBuffer.push({server, "Backup"});
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
        std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    }
}

std::queue<std::string> UDPServer::serializeDatabase()
{
    std::queue<std::string> serializedDatabase;
    serializedDatabase.push("Backup/");
    for (const auto &server : otherServers)
    {
        std::string serverIp = inet_ntoa(server.sin_addr);
        std::string serverPort = std::to_string((server.sin_port));
        std::string serializedData = serverIp + "," + serverPort + ";";
        serializedDatabase.push(serializedData);
    }
    serializedDatabase.push("/");
    std::queue<twt::Message> tempMessageBuffer = messageBuffer;
    while (!tempMessageBuffer.empty())
    {
        twt::Message message = tempMessageBuffer.front();
        std::string serializedData = std::to_string(message.timestamp) + "," + std::to_string(message.sender.userId)  + "," + message.sender.username + "," + message.content + ";";
        serializedDatabase.push(serializedData);
        tempMessageBuffer.pop();
    }
    serializedDatabase.push("29062001,420,Pedro,O Dick não ama JP bagrão;");
    serializedDatabase.push("07022004,69,Gabriel,O Dick (M)ama JP bagrão;");
    serializedDatabase.push("/");
    for (auto &user : read_file(database_name))
    {
        serializedDatabase.push(format_data(user));
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

int main(int argc, char *argv[])
{
    int porta_main, port_server_replica;
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

    UDPServer serverServer(port_server_replica, porta_main, ip);
    UDPServer clientServer(PORT);

    std::thread serverThread(&UDPServer::start_replication, &serverServer);
    // std::thread clientThread(&UDPServer::start, &clientServer);

    serverThread.join();
    // clientThread.join();

    return 0;
}
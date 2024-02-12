#ifndef SERVER
#define SERVER
#define SERVER_RECV_DEBUG false

#include <iostream>
#include <vector>
#include <set>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <cstring>
#include <arpa/inet.h>
#include "../../common/header/data.hpp"
#include "../../assets/constraints.hpp"
#include "../../database/database.hpp"
#include "../../common/header/serialize.hpp"

struct PacketInfo {
    twt::Packet packet;
    sockaddr_in clientAddress;
};

class UDPServer {
public:
    UDPServer(int port, int mainServerPort, std::string mainServerIP);
    UDPServer(int port);
    ~UDPServer();
    void start();
    void start_replication();
    twt::Followers followers;
    twt::UsersList usersList;
    std::string database_name = "assets/database.txt";
    
    void displayUserList();
    void displayFollowersList();

    std::unordered_map<int, twt::UserInfo> getUsersList();

    void resetSequenceNumber(const sockaddr_in& clientAddress);
    // Adicionando função para verificar se o pacote é repetido
    bool isPacketRepeated(const sockaddr_in& clientAddress, const twt::Packet& pack);
    void updateSequenceNumber(const sockaddr_in& clientAddress, uint16_t newSequenceNumber);
    bool isSequenceNumberValid(const sockaddr_in& clientAddress, const twt::Packet& pack);

private:
    
    int  myServerPort;
    bool isAckReceived;
    bool isMainServerUp;
    bool waitForAck();
    void sendPacketWithRetransmission(const sockaddr_in& clientAddress, std::string returnMassage);


    std::unordered_map<uint32_t, std::unordered_map<uint16_t, uint16_t>> lastSequenceNumber;

    void handlePackets();
    void loadFollowersIntoUsersList();
    void saveFollowersFromUsersList();
    void processPacket();
    void saveDataBase();
    void loadDataBase();
    void processMessages();
    void processLogin();
    void Ping();
    void PingReply();
    void processPacket_server();
    void processPingMessage(sockaddr_in clientAddress);
    void sendBackupPacket();
    void handleLogout(const sockaddr_in& clientAddress, int id);
    void sendBufferedMessages(int userId);
    bool isPacketRepeated(const twt::Packet& pack, const sockaddr_in& clientAddress);
    void broadcastMessage(int receiverId);
    bool UserConnected(int userId);
    void sendPacket();
    std::queue<std::string> serializeDatabase();
    void processBackup(const std::string& input);

    std::vector<sockaddr_in> otherServers; // IP, Porta
    int serverSocket;
    std::queue<sockaddr_in> pingQueue;
    std::queue<std::pair<const sockaddr_in&, const std::string>> processingBuffer;
    std::queue<std::pair<const sockaddr_in&, const std::string>> sendBuffer;
    std::string mainServerIP;
    int mainServerPort;
    bool isMainServer;
    void electionMainServer(); 
    std::unordered_map<int, std::vector<sockaddr_in>> connectedUsers;  // User ID -> Set of connected sessions
    std::deque<PacketInfo> packetBuffer;
    std::unordered_map<int, std::queue<twt::Message>> userMessageBuffer, msgToSendBuffer;  // User ID -> Queue of stored messages
    std::queue<twt::Message> messageBuffer; // Messages of the tr
    std::queue<std::pair<std::pair<int, std::pair<in_addr_t, in_port_t>>, sockaddr_in>> electionQueue;
    std::queue<std::pair<const sockaddr_in&, const std::string&>> loginBuffer;
    std::map<std::pair<int, std::pair<in_addr_t, in_port_t>>, sockaddr_in> pingSet;
    std::mutex mutexProcBuff;
    std::mutex mutexLogElection;
    std::mutex mutexUsers;
    std::mutex mutexMsgBuff;
    std::mutex mutexLogBuff;
    std::mutex mutexLogPing;
    std::mutex mutexServerSend;
    bool running;

    

};



#endif
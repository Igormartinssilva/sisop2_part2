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
#include <ifaddrs.h>
#include "../../common/header/data.hpp"
#include "../../assets/constraints.hpp"
#include "../../database/database.hpp"
#include "../../common/header/serialize.hpp"
//#include "election.hpp"

struct PacketInfo {
    twt::Packet packet;
    sockaddr_in clientAddress;
};

//class Election;

class UDPServer {
public:
    UDPServer(int port, int mainServerPort, std::string mainServerIP, int serverId);
    UDPServer(int port);
    ~UDPServer();
    void start();
    void start_replication();
    twt::Followers followers;
    twt::UsersList usersList;
    std::string database_name = "assets/database.txt";
    
    void displayUserList();
    void displayFollowersList();

    bool running;
    std::unordered_map<int, twt::UserInfo> getUsersList();

    void resetSequenceNumber(const sockaddr_in& clientAddress);
    // Adicionando função para verificar se o pacote é repetido
    bool isPacketRepeated(const sockaddr_in& clientAddress, const twt::Packet& pack);
    void updateSequenceNumber(const sockaddr_in& clientAddress, uint16_t newSequenceNumber);
    bool isSequenceNumberValid(const sockaddr_in& clientAddress, const twt::Packet& pack);

private:
    int greatestResponsePort;
    std::string greatestResponseIp;
    int  myServerPort;
    bool isAckReceived;
    bool isMainServerUp;
    bool waitForAck();
    void sendPacketWithRetransmission(const sockaddr_in& clientAddress, std::string returnMassage);
    std::string calcID(sockaddr_in Address);
    sockaddr_in toSockaddr(int port, std::string ip);
        //Election election;

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
    void anounceMainServer();
    void broadcastMessage(int receiverId);
    bool UserConnected(int userId);
    void sendPacket();
    std::string getIPAddress();
    std::queue<std::string> serializeDatabase();
    void processBackup(const std::string& input);
    void processElectionResult(const std::string& input);
    void processElectionRequest(const std::string& input, const sockaddr_in& clientaddr);
    void processElectionRequestAck(const std::string &packet, const sockaddr_in& clientaddr);

    std::vector<sockaddr_in> otherServers; 
    int serverSocket;
    std::queue<sockaddr_in> pingQueue;
    std::queue<std::pair<const sockaddr_in&, const std::string>> processingBuffer;
    std::queue<std::pair<const sockaddr_in&, const std::string>> sendBuffer;
    std::string mainServerIP;
    int mainServerPort;
    int serverId;
    
    void electionMainServer(); 
    //std::vector<std::pair<int, std::string>> getHigherIds();
    std::pair<int, std::string> startElection(std::vector<std::pair<std::string, int>> serversToSend);
    void sendElectionResult(int port, std::string ip);
    std::vector<std::pair<std::string, int>> getHigherIds(const std::vector<sockaddr_in>& otherServers);
    
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

    

};



#endif
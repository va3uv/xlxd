//
//  cdextraprotocol.cpp
//  xlxd
// ...existing code...

// Implementation moved to correct class scope below

// ----------------------------------------------------------------------------
//    This file is part of xlxd.
//
//    xlxd is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    xlxd is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with Foobar.  If not, see <http://www.gnu.org/licenses/>. 
// ----------------------------------------------------------------------------

#include "main.h"
#include "ccallsign.h"
#include "cpacketstream.h"
#include <mutex>
#include <vector>
#include <string.h>
#include <fstream>
#include <sstream>
#include "cdextraclient.h"
#include "cdextraprotocol.h"
#include "creflector.h"
#include "cgatekeeper.h"
#include <netdb.h>
#include <arpa/inet.h>
// Constructor/Destructor
CDextraProtocol::CDextraProtocol() : CProtocol() {
    // std::clog << "[DExtra] CDextraProtocol constructor called" << std::endl;
}
CDextraProtocol::~CDextraProtocol() {}

// Load DExtra peers from config file
void CDextraProtocol::LoadDExtraPeers(const std::string& filename) {
    // Print peer list before reload
    {
        std::lock_guard<std::mutex> lock(m_logMutex);
        std::clog << "[DExtra][DEBUG] Peer list BEFORE reload:" << std::endl;
    }
    for (const auto& peer : m_DExtraPeers) {
        {
            std::lock_guard<std::mutex> lock(m_logMutex);
            std::clog << "[DExtra][DEBUG]   callsign='" << peer.remoteCallsign << "' IP='" << peer.remoteIp << "' localModule='" << peer.localModule << "' remoteModule='" << peer.remoteModule << "' handshakeComplete=" << (peer.handshakeComplete ? "true" : "false") << std::endl;
        }
    }
    // Preserve handshakeComplete for unchanged peers
    std::vector<DExtraPeerConfig> oldPeers = m_DExtraPeers;
    m_DExtraPeers.clear();
    std::ifstream infile(filename);
    std::string line;
    int lineNum = 0;
    while (std::getline(infile, line)) {
        lineNum++;
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::istringstream iss(line);
        std::string typeOrCallsign, ip, modules;
        if (!(iss >> typeOrCallsign >> ip >> modules)) {
            continue;
        }
        if (modules.length() < 2) {
            continue;
        }
        DExtraPeerConfig peer;
        // Resolve hostname to IP if needed
        std::string resolvedIp = ip;
        struct addrinfo hints = {0}, *res = nullptr;
        hints.ai_family = AF_INET;
        int err = getaddrinfo(ip.c_str(), nullptr, &hints, &res);
        if (err == 0 && res != nullptr) {
            char ipstr[INET_ADDRSTRLEN] = {0};
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
            inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
            resolvedIp = ipstr;
            freeaddrinfo(res);
        }
        peer.remoteIp = resolvedIp;
        peer.localModule = modules[0];
        peer.remoteModule = modules[1];
        if (typeOrCallsign.substr(0,3) == "XRF") {
            peer.type = PEER_DEXTRA;
            peer.remoteCallsign = typeOrCallsign;
        } else if (typeOrCallsign.substr(0,3) == "XLX") {
            peer.type = PEER_XLX;
            peer.remoteCallsign = typeOrCallsign;
        } else {
            continue;
        }
        // Try to find a matching old peer to preserve handshakeComplete
        for (const auto& oldPeer : oldPeers) {
            if (oldPeer.type == peer.type && oldPeer.remoteCallsign == peer.remoteCallsign && oldPeer.remoteIp == peer.remoteIp && oldPeer.localModule == peer.localModule && oldPeer.remoteModule == peer.remoteModule) {
                peer.handshakeComplete = oldPeer.handshakeComplete;
                {
                    std::lock_guard<std::mutex> lock(m_logMutex);
                    std::clog << "[DExtra][DEBUG] Preserved handshakeComplete for peer " << peer.remoteCallsign << " at " << peer.remoteIp << " = " << (peer.handshakeComplete ? "true" : "false") << std::endl;
                }
                break;
            }
        }
        m_DExtraPeers.push_back(peer);
        {
            std::lock_guard<std::mutex> lock(m_logMutex);
            std::clog << "[DExtra][DEBUG] Added peer: callsign='" << peer.remoteCallsign << "' IP='" << peer.remoteIp << "' localModule='" << peer.localModule << "' remoteModule='" << peer.remoteModule << "' handshakeComplete=" << (peer.handshakeComplete ? "true" : "false") << std::endl;
        }
    }

    // Remove clients for peers no longer in config
    // (call after m_DExtraPeers is rebuilt)
    CClients *clients = g_Reflector.GetClients();
    for (const auto& oldPeer : oldPeers) {
        bool found = false;
        for (const auto& peer : m_DExtraPeers) {
            if (oldPeer.type == peer.type && oldPeer.remoteCallsign == peer.remoteCallsign && oldPeer.remoteIp == peer.remoteIp && oldPeer.localModule == peer.localModule && oldPeer.remoteModule == peer.remoteModule) {
                found = true;
                break;
            }
        }
        if (!found && oldPeer.handshakeComplete) {
            {
                std::lock_guard<std::mutex> lock(m_logMutex);
                std::clog << "[DExtra][DEBUG] Removing client for peer: callsign='" << oldPeer.remoteCallsign << "' IP='" << oldPeer.remoteIp << "' localModule='" << oldPeer.localModule << "' remoteModule='" << oldPeer.remoteModule << "' handshakeComplete=" << (oldPeer.handshakeComplete ? "true" : "false") << std::endl;
            }
            // Remove client for this peer
            CIp ip(oldPeer.remoteIp.c_str());
            CClient *client = clients->FindClient(ip, PROTOCOL_DEXTRA);
            if (client != NULL) {
                void CDextraProtocol::EncodeKeepAlivePacket(CBuffer *Buffer)
                {
                    Buffer->Set(GetReflectorCallsign());
                }

                clients->RemoveClient(client);
                {
                    std::lock_guard<std::mutex> lock(m_logMutex);
                    std::clog << "[DExtra][DEBUG] Client removed for peer: callsign='" << oldPeer.remoteCallsign << "' IP='" << oldPeer.remoteIp << "'" << std::endl;
                }
            } else {
                {
                    std::lock_guard<std::mutex> lock(m_logMutex);
                    std::clog << "[DExtra][DEBUG] No client found to remove for peer: callsign='" << oldPeer.remoteCallsign << "' IP='" << oldPeer.remoteIp << "'" << std::endl;
                }
            }
        }
    }
    g_Reflector.ReleaseClients();
    // Deduplicate peers after loading
    {
        std::vector<DExtraPeerConfig> dedupedPeers;
        for (const auto& peer : m_DExtraPeers) {
            bool found = false;
            for (auto& existing : dedupedPeers) {
                if (peer.type == existing.type &&
                    peer.remoteCallsign == existing.remoteCallsign &&
                    peer.remoteIp == existing.remoteIp &&
                    peer.localModule == existing.localModule &&
                    peer.remoteModule == existing.remoteModule) {
                    // If either has handshakeComplete true, keep it true
                    if (peer.handshakeComplete || existing.handshakeComplete) {
                        existing.handshakeComplete = true;
                    }
                    found = true;
                    {
                        std::lock_guard<std::mutex> lock(m_logMutex);
                        std::clog << "[DExtra][WARNING] Duplicate peer in config: callsign='" << peer.remoteCallsign << "' IP='" << peer.remoteIp << "' localModule='" << peer.localModule << "' remoteModule='" << peer.remoteModule << "'. Only the first occurrence with handshakeComplete=true will be used." << std::endl;
                    }
                    break;
                }
            }
            if (!found) {
                dedupedPeers.push_back(peer);
            }
        }
        m_DExtraPeers = dedupedPeers;
    }
    // Print peer list after reload
    {
        std::lock_guard<std::mutex> lock(m_logMutex);
        std::clog << "[DExtra][DEBUG] Peer list AFTER reload:" << std::endl;
    }
    for (const auto& peer : m_DExtraPeers) {
        {
            std::lock_guard<std::mutex> lock(m_logMutex);
            std::clog << "[DExtra][DEBUG]   callsign='" << peer.remoteCallsign << "' IP='" << peer.remoteIp << "' localModule='" << peer.localModule << "' remoteModule='" << peer.remoteModule << "' handshakeComplete=" << (peer.handshakeComplete ? "true" : "false") << std::endl;
        }
    }
}

// Encode a DExtra connect packet
void CDextraProtocol::EncodeConnectPacket(const std::string& localCallsign, char localModule, const std::string& remoteCallsign, char remoteModule, CBuffer* buffer) {
    // DExtra connect packet: 11 bytes: 8 (callsign) + 1 (local module) + 1 (remote module) + 1 (revision=0)
    buffer->clear();
    char cs[9] = {0};
    strncpy(cs, localCallsign.c_str(), 8);
    buffer->Append((uint8*)cs, 8);
    buffer->Append((uint8)localModule);
    buffer->Append((uint8)remoteModule);
    buffer->Append((uint8)0); // revision 0
}

// Send connect packets to all configured peers
void CDextraProtocol::PeerWithConfiguredXLX() {
    // Use the local reflector callsign for outgoing connects
    char cs[9] = {0};
    GetReflectorCallsign().GetCallsignString(cs);
    std::string localCallsign(cs);
    // std::clog << "[DExtra] PeerWithConfiguredXLX() called, " << m_DExtraPeers.size() << " peers configured" << std::endl;
    for (auto& peer : m_DExtraPeers) {
        if (peer.type == PEER_DEXTRA) {
            std::clog << "[DExtra][DEBUG] Peer connect check: callsign='" << peer.remoteCallsign << "' IP='" << peer.remoteIp << "' handshakeComplete=" << (peer.handshakeComplete ? "true" : "false") << std::endl;
            if (!peer.handshakeComplete) {
                CIp remoteIp(peer.remoteIp.c_str());
                CBuffer connectPacket;
                EncodeConnectPacket(localCallsign, peer.localModule, peer.remoteCallsign, peer.remoteModule, &connectPacket);
                // std::clog << "[DEBUG] Sending DExtra connect to " << peer.remoteCallsign << " at " << peer.remoteIp << ":" << DEXTRA_PORT << std::endl;
                m_Socket.Send(connectPacket, remoteIp, DEXTRA_PORT);
                std::cout << "[DExtra] Sent connect to " << peer.remoteCallsign << " at " << peer.remoteIp << ":" << DEXTRA_PORT << " (local module " << peer.localModule << ", remote module " << peer.remoteModule << ")" << std::endl;
            } else {
                // Optionally, send keepalives here if needed
            }
        } else if (peer.type == PEER_XLX) {
            // TODO: Implement XLX peering logic here, using port 10002
            std::cout << "[DEBUG] Would send XLX connect to " << peer.remoteCallsign << " at " << peer.remoteIp << ":10002" << std::endl;
            std::cout << "[XLX] Would send XLX connect to " << peer.remoteCallsign << " at " << peer.remoteIp << ":10002 (local module " << peer.localModule << ", remote module " << peer.remoteModule << ")" << std::endl;
        }
    }
}


////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CDextraProtocol::Init(void)
{
    bool ok;
    // base class
    ok = CProtocol::Init();
    // update the reflector callsign
    m_ReflectorCallsign.PatchCallsign(0, (const uint8 *)"XRF", 3);
    // create our socket
    ok &= m_Socket.Open(DEXTRA_PORT);
    if (!ok) {
        std::cout << "Error opening socket on port UDP" << DEXTRA_PORT << " on ip " << g_Reflector.GetListenIp() << std::endl;
    }
    // update time
    m_LastKeepaliveTime.Now();
    m_LastPeerTime.Now();
    // Load peers from config
    LoadDExtraPeers("/xlxd/xlxd.interlink");
    // done
    return ok;
}

////////////////////////////////////////////////////////////////////////////////////////
// task

void CDextraProtocol::Task()
{
    CBuffer             Buffer;
    CIp                 Ip;
    CCallsign           Callsign;
    char                ToLinkModule;
    int                 ProtRev;
    CDvHeaderPacket     *Header;
    CDvFramePacket      *Frame;
    CDvLastFramePacket  *LastFrame;

    // Periodically reload peers from config and peer with configured XLX reflectors (every 10 seconds)
    if (m_LastPeerTime.DurationSinceNow() > 10) {
        LoadDExtraPeers("/xlxd/xlxd.interlink");
        PeerWithConfiguredXLX();
        m_LastPeerTime.Now();
    }
    // any incoming packet ?
        // Log every incoming packet: size and first 8 bytes
        {
            std::lock_guard<std::mutex> lock(m_logMutex);
            std::clog << "[DExtra][DEBUG] Incoming UDP packet from IP='" << Ip << "' size=" << Buffer.size() << " bytes: ";
            for (size_t i = 0; i < Buffer.size() && i < 8; ++i) {
                std::clog << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)Buffer.data()[i] << " ";
            }
            std::clog << std::dec << std::endl;
        }
        // ...existing code for handling packets...
        if ( (Frame = IsValidDvFramePacket(Buffer)) != NULL ) {
            OnDvFramePacketIn(Frame, &Ip);
        } else if ( (Header = IsValidDvHeaderPacket(Buffer)) != NULL ) {
            if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, PROTOCOL_DEXTRA, Header->GetRpt2Module()) ) {
                OnDvHeaderPacketIn(Header, Ip);
            } else {
                delete Header;
            }
        } else if ( (LastFrame = IsValidDvLastFramePacket(Buffer)) != NULL ) {
            OnDvLastFramePacketIn(LastFrame, &Ip);
        } else if (Buffer.size() == 14) {
            // 8 bytes: callsign, 1: local module, 1: remote module, 1: 0, 3: 'ACK' or 'NAK' or 0
            char callsign[9] = {0};
            memcpy(callsign, Buffer.data(), 8);
            char localModule = Buffer.data()[8];
            char remoteModule = Buffer.data()[9];
            // Mark handshake complete for this peer (for any valid 14-byte packet)
            std::string normCallsign(callsign);
            normCallsign.resize(8, ' ');
            std::string pktIpStr = std::string((const char*)Ip);
            for (auto& peer : m_DExtraPeers) {
                std::string peerNormCallsign = peer.remoteCallsign;
                peerNormCallsign.resize(8, ' ');
                std::string peerIpStr = peer.remoteIp;
                if (peerNormCallsign == normCallsign && peerIpStr == pktIpStr && peer.localModule == localModule && peer.remoteModule == remoteModule) {
                    peer.handshakeComplete = true;
                }
            }
            // Add a client for this remote if not already present
            CClients *clients = g_Reflector.GetClients();
            if (clients->FindClient(Ip, PROTOCOL_DEXTRA) == NULL) {
                CDextraClient *client = new CDextraClient(CCallsign(callsign), Ip, localModule, 2);
                clients->AddClient(client);
                {
                    std::lock_guard<std::mutex> lock(m_logMutex);
                    std::clog << "[DExtra][DEBUG] Created new DExtra client for callsign='" << callsign << "' IP='" << Ip << "' module='" << localModule << "'" << std::endl;
                }
            }
            g_Reflector.ReleaseClients();
        }
        else if ( IsValidConnectPacket(Buffer, &Callsign, &ToLinkModule, &ProtRev) )
            {
                std::cout << "DExtra connect packet for module " << ToLinkModule << " from " << Callsign << " at " << Ip << " rev " << ProtRev << std::endl;
                // Mark handshake complete for this peer (for any valid connect packet, match on callsign and IP only)
                char cs[9] = {0};
                Callsign.GetCallsignString(cs);
                std::string normCallsign(cs);
                normCallsign.resize(8, ' ');
                std::string pktIpStr = std::string((const char*)Ip);
                bool matchedPeer = false;
                std::clog << "[DExtra][DEBUG] Incoming connect: callsign='" << normCallsign << "' IP='" << pktIpStr << "' module='" << ToLinkModule << "'" << std::endl;
                for (auto& peer : m_DExtraPeers) {
                    std::string peerNormCallsign = peer.remoteCallsign;
                    peerNormCallsign.resize(8, ' ');
                    std::string peerIpStr = peer.remoteIp;
                    std::clog << "[DExtra][DEBUG] Configured peer: callsign='" << peerNormCallsign << "' IP='" << peerIpStr << "' localModule='" << peer.localModule << "' remoteModule='" << peer.remoteModule << "'" << std::endl;
                    if (peerNormCallsign == normCallsign && peerIpStr == pktIpStr) {
                        if (!peer.handshakeComplete) {
                            std::clog << "[DExtra] Handshake complete for peer " << peer.remoteCallsign << " at " << peer.remoteIp << std::endl;
                        }
                        peer.handshakeComplete = true;
                        matchedPeer = true;
                    }
                }
                // Only respond with ACK/NAK, do not send another connect
                if (matchedPeer) {
                    if (g_GateKeeper.MayLink(Callsign, Ip, PROTOCOL_DEXTRA) && g_Reflector.IsValidModule(ToLinkModule)) {
                        CBuffer ackBuffer;
                        ackBuffer = Buffer; // Copy connect packet as base
                        if ( m_Socket.Receive(&Buffer, &Ip, 20) != -1 )
                        {
                            // Log every incoming packet: size and first 8 bytes
                            {
                                std::lock_guard<std::mutex> lock(m_logMutex);
                                std::clog << "[DExtra][DEBUG] Incoming UDP packet from IP='" << Ip << "' size=" << Buffer.size() << " bytes: ";
                                for (size_t i = 0; i < Buffer.size() && i < 8; ++i) {
                                    std::clog << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)Buffer.data()[i] << " ";
                                }
                                std::clog << std::dec << std::endl;
                            }
                            // ...existing code for handling packets...
                            if ( (Frame = IsValidDvFramePacket(Buffer)) != NULL )
                            {
                                OnDvFramePacketIn(Frame, &Ip);
                            }
                            else if ( (Header = IsValidDvHeaderPacket(Buffer)) != NULL )
                            {
                                if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, PROTOCOL_DEXTRA, Header->GetRpt2Module()) )
                                {
                                    OnDvHeaderPacketIn(Header, Ip);
                                }
                                else
                                {
                                    delete Header;
                                }
                            }
                            else if ( (LastFrame = IsValidDvLastFramePacket(Buffer)) != NULL )
                            {
                                OnDvLastFramePacketIn(LastFrame, &Ip);
                            }
                            // --- DExtra handshake/acknowledgment packet (14 bytes) ---
                            else if (Buffer.size() == 14) {
                                // 8 bytes: callsign, 1: local module, 1: remote module, 1: 0, 3: 'ACK' or 'NAK' or 0
                                char callsign[9] = {0};
                                memcpy(callsign, Buffer.data(), 8);
                                char localModule = Buffer.data()[8];
                                char remoteModule = Buffer.data()[9];
                                // Mark handshake complete for this peer (for any valid 14-byte packet)
                                std::string normCallsign(callsign);
                                normCallsign.resize(8, ' ');
                                std::string pktIpStr = std::string((const char*)Ip);
                                for (auto& peer : m_DExtraPeers) {
                                    std::string peerNormCallsign = peer.remoteCallsign;
                                    peerNormCallsign.resize(8, ' ');
                                    std::string peerIpStr = peer.remoteIp;
                                    if (peerNormCallsign == normCallsign && peerIpStr == pktIpStr && peer.localModule == localModule && peer.remoteModule == remoteModule) {
                                        peer.handshakeComplete = true;
                                    }
                                }
                                // Add a client for this remote if not already present
                                CClients *clients = g_Reflector.GetClients();
                                if (clients->FindClient(Ip, PROTOCOL_DEXTRA) == NULL) {
                                    CDextraClient *client = new CDextraClient(CCallsign(callsign), Ip, localModule, 2);
                                    clients->AddClient(client);
                                    {
                                        std::lock_guard<std::mutex> lock(m_logMutex);
                                        std::clog << "[DExtra][DEBUG] Created new DExtra client for callsign='" << callsign << "' IP='" << Ip << "' module='" << localModule << "'" << std::endl;
                                    }
                                }
                                g_Reflector.ReleaseClients();
                            }
                            else if ( IsValidConnectPacket(Buffer, &Callsign, &ToLinkModule, &ProtRev) )
                            {
                                std::cout << "DExtra connect packet for module " << ToLinkModule << " from " << Callsign << " at " << Ip << " rev " << ProtRev << std::endl;
                                // Mark handshake complete for this peer (for any valid connect packet, match on callsign and IP only)
                                char cs[9] = {0};
                                Callsign.GetCallsignString(cs);
                                std::string normCallsign(cs);
                                normCallsign.resize(8, ' ');
                                std::string pktIpStr = std::string((const char*)Ip);
                                bool matchedPeer = false;
                                std::clog << "[DExtra][DEBUG] Incoming connect: callsign='" << normCallsign << "' IP='" << pktIpStr << "' module='" << ToLinkModule << "'" << std::endl;
                                for (auto& peer : m_DExtraPeers) {
                                    std::string peerNormCallsign = peer.remoteCallsign;
                                    peerNormCallsign.resize(8, ' ');
                                    std::string peerIpStr = peer.remoteIp;
                                    std::clog << "[DExtra][DEBUG] Configured peer: callsign='" << peerNormCallsign << "' IP='" << peerIpStr << "' localModule='" << peer.localModule << "' remoteModule='" << peer.remoteModule << "'" << std::endl;
                                    if (peerNormCallsign == normCallsign && peerIpStr == pktIpStr) {
                                        if (!peer.handshakeComplete) {
                                            std::clog << "[DExtra] Handshake complete for peer " << peer.remoteCallsign << " at " << peer.remoteIp << std::endl;
                                        }
                                        peer.handshakeComplete = true;
                                        matchedPeer = true;
                                    }
                                }
                                // Only respond with ACK/NAK, do not send another connect
                                if (matchedPeer) {
                                    if (g_GateKeeper.MayLink(Callsign, Ip, PROTOCOL_DEXTRA) && g_Reflector.IsValidModule(ToLinkModule)) {
                                        CBuffer ackBuffer;
                                        ackBuffer = Buffer; // Copy connect packet as base
                                        EncodeConnectAckPacket(&ackBuffer, ProtRev);
                                        m_Socket.Send(ackBuffer, Ip);
                                        // Add client if not already present
                                        CClients *clients = g_Reflector.GetClients();
                                        if (clients->FindClient(Ip, PROTOCOL_DEXTRA) == NULL) {
                                            CDextraClient *client = new CDextraClient(Callsign, Ip, ToLinkModule, ProtRev);
                                            clients->AddClient(client);
                                            {
                                                std::lock_guard<std::mutex> lock(m_logMutex);
                                                std::clog << "[DExtra][DEBUG] Created new DExtra client for callsign='" << Callsign << "' IP='" << Ip << "' module='" << ToLinkModule << "'" << std::endl;
                                            }
                                        }
                                        g_Reflector.ReleaseClients();
                                    } else {
                                        CBuffer nackBuffer;
                                        nackBuffer = Buffer;
                                        EncodeConnectNackPacket(&nackBuffer);
                                        m_Socket.Send(nackBuffer, Ip);
                                    }
                                } else {
                                    // Only send NAK if not a configured peer
                                    CBuffer nackBuffer;
                                    nackBuffer = Buffer;
                                    EncodeConnectNackPacket(&nackBuffer);
                                    std::clog << "[DExtra] Sending 14-byte NAK to " << Callsign << " at " << Ip << " (not a configured peer)" << std::endl;
                                    std::clog << "[DExtra] NAK Raw packet: ";
                                    for (size_t i = 0; i < nackBuffer.size(); ++i) {
                                        std::clog << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)nackBuffer.data()[i] << " ";
                                    }
                                    std::clog << std::dec << std::endl;
                                    m_Socket.Send(nackBuffer, Ip);
                                }
                            }
                            else if ( IsValidDisconnectPacket(Buffer, &Callsign) )
                            {
                                std::cout << "DExtra disconnect packet from " << Callsign << " at " << Ip << std::endl;
                                CClients *clients = g_Reflector.GetClients();
                                CClient *client = clients->FindClient(Ip, PROTOCOL_DEXTRA);
                                if ( client != NULL )
                                {
                                    if ( client->GetProtocolRevision() == 1 )
                                    {
                                        EncodeDisconnectedPacket(&Buffer);
                                        m_Socket.Send(Buffer, Ip);
                                    }
                                    else if ( client->GetProtocolRevision() == 2 )
                                    {
                                        m_Socket.Send(Buffer, Ip);
                                    }
                                    clients->RemoveClient(client);
                                }
                                g_Reflector.ReleaseClients();
                            }
                            else if ( IsValidKeepAlivePacket(Buffer, &Callsign) )
                            {
                                // Only respond to keepalives from currently configured peers
                                char cs[9] = {0};
                                Callsign.GetCallsignString(cs);
                                std::string normCallsign(cs);
                                normCallsign.resize(8, ' ');
                                std::string pktIpStr = std::string((const char*)Ip);
                                bool peerFound = false;
                                std::clog << "[DExtra][DEBUG] Incoming keepalive: callsign='" << normCallsign << "' IP='" << pktIpStr << "'" << std::endl;
                                for (auto& peer : m_DExtraPeers) {
                                    std::string peerNormCallsign = peer.remoteCallsign;
                                    peerNormCallsign.resize(8, ' ');
                                    std::string peerIpStr = peer.remoteIp;
                                    std::clog << "[DExtra][DEBUG] Configured peer: callsign='" << peerNormCallsign << "' IP='" << peerIpStr << "'" << std::endl;
                                    if (peerNormCallsign == normCallsign && peerIpStr == pktIpStr) {
                                        if (!peer.handshakeComplete) {
                                            std::clog << "[DExtra] Handshake complete for peer (keepalive) " << peer.remoteCallsign << " at " << peer.remoteIp << std::endl;
                                        }
                                        peer.handshakeComplete = true;
                                        peerFound = true;
                                    }
                                }
                                if (peerFound) {
                                    CClients *clients = g_Reflector.GetClients();
                                    int index = -1;
                                    CClient *client = NULL;
                                    while ( (client = clients->FindNextClient(Callsign, Ip, PROTOCOL_DEXTRA, &index)) != NULL )
                                    {
                                       client->Alive();
                                    }
                                    g_Reflector.ReleaseClients();
                                } else {
                                    std::clog << "[DExtra][DEBUG] Ignored keepalive from unknown peer: callsign='" << normCallsign << "' IP='" << pktIpStr << "'" << std::endl;
                                }
                            }
                            else
                            {
                                std::cout << "DExtra packet (" << Buffer.size() << ")" << std::endl;
                            }

                            // handle end of streaming timeout
                            CheckStreamsTimeout();
                            // handle queue from reflector
                            HandleQueue();
                            // keep client alive
                            if ( m_LastKeepaliveTime.DurationSinceNow() > DEXTRA_KEEPALIVE_PERIOD )
                            {
                                HandleKeepalives();
                                m_LastKeepaliveTime.Now();
                            }
                        }
                    }
                }
            }
        }
    }
    // handle end of streaming timeout
    CheckStreamsTimeout();
    // handle queue from reflector
    HandleQueue();
    // keep client alive
    if ( m_LastKeepaliveTime.DurationSinceNow() > DEXTRA_KEEPALIVE_PERIOD )
    {
        HandleKeepalives();
        m_LastKeepaliveTime.Now();
    }
}

////////////////////////////////////////////////////////////////////////////////////////
// packet decoding helpers

bool CDextraProtocol::IsValidConnectPacket(const CBuffer &Buffer, CCallsign *callsign, char *reflectormodule, int *revision)
{
    bool valid = false;
    if ((Buffer.size() == 11) && (Buffer.data()[9] != ' '))
    {
        callsign->SetCallsign(Buffer.data(), 8);
        callsign->SetModule(Buffer.data()[8]);
        *reflectormodule = Buffer.data()[9];
        *revision = (Buffer.data()[10] == 11) ? 1 : 0;
        valid = (callsign->IsValid() && IsLetter(*reflectormodule));
        // detect revision
        if ( (Buffer.data()[10] == 11) )
        {
            *revision = 1;
        }
        else if ( callsign->HasSameCallsignWithWildcard(CCallsign("XRF*")) )
        {
            *revision = 2;
        }
        else
        {
            *revision = 0;
        }
    }
    return valid;
}

bool CDextraProtocol::IsValidDisconnectPacket(const CBuffer &Buffer, CCallsign *callsign)
{
    bool valid = false;
    if ((Buffer.size() == 11) && (Buffer.data()[9] == ' '))
    {
        callsign->SetCallsign(Buffer.data(), 8);
        callsign->SetModule(Buffer.data()[8]);
       valid = callsign->IsValid();
    }
    return valid;
}

bool CDextraProtocol::IsValidKeepAlivePacket(const CBuffer &Buffer, CCallsign *callsign)
{
    bool valid = false;
    if (Buffer.size() == 9)
    {
        callsign->SetCallsign(Buffer.data(), 8);
        valid = callsign->IsValid();
    }
    return valid;
}

CDvHeaderPacket *CDextraProtocol::IsValidDvHeaderPacket(const CBuffer &Buffer)
{
    CDvHeaderPacket *header = NULL;
    
    if ( (Buffer.size() == 56) && (Buffer.Compare((uint8 *)"DSVT", 4) == 0) &&
         (Buffer.data()[4] == 0x10) && (Buffer.data()[8] == 0x20) )
    {
        // create packet
        header = new CDvHeaderPacket((struct dstar_header *)&(Buffer.data()[15]),
                                *((uint16 *)&(Buffer.data()[12])), 0x80);
        // check validity of packet
        if ( !header->IsValid() )
        {
            delete header;
            header = NULL;
        }
    }
    return header;
}

CDvFramePacket *CDextraProtocol::IsValidDvFramePacket(const CBuffer &Buffer)
{
    CDvFramePacket *dvframe = NULL;
    
    if ( (Buffer.size() == 27) && (Buffer.Compare((uint8 *)"DSVT", 4) == 0) &&
         (Buffer.data()[4] == 0x20) && (Buffer.data()[8] == 0x20) &&
         ((Buffer.data()[14] & 0x40) == 0) )
    {
        // create packet
        dvframe = new CDvFramePacket((struct dstar_dvframe *)&(Buffer.data()[15]),
                                     *((uint16 *)&(Buffer.data()[12])), Buffer.data()[14]);
        // check validity of packet
        if ( !dvframe->IsValid() )
        {
            delete dvframe;
            dvframe = NULL;
        }
    }
    return dvframe;
}

CDvLastFramePacket *CDextraProtocol::IsValidDvLastFramePacket(const CBuffer &Buffer)
{
    CDvLastFramePacket *dvframe = NULL;
    
    if ( (Buffer.size() == 27) && (Buffer.Compare((uint8 *)"DSVT", 4) == 0) &&
         (Buffer.data()[4] == 0x20) && (Buffer.data()[8] == 0x20) &&
         ((Buffer.data()[14] & 0x40) != 0) )
    {
        // create packet
        dvframe = new CDvLastFramePacket((struct dstar_dvframe *)&(Buffer.data()[15]),
                                         *((uint16 *)&(Buffer.data()[12])), Buffer.data()[14]);
        // check validity of packet
        if ( !dvframe->IsValid() )
        {
            delete dvframe;
            dvframe = NULL;
        }
    }
    return dvframe;
}

////////////////////////////////////////////////////////////////////////////////////////
// packet encoding helpers

void CDextraProtocol::EncodeKeepAlivePacket(CBuffer *Buffer)
bool CDextraProtocol::OnDvHeaderPacketIn(CDvHeaderPacket *Header, const CIp &Ip)
{
    // Debug log for header packet arrival
    {
        std::lock_guard<std::mutex> lock(m_logMutex);
        std::clog << "[DExtra][DEBUG] OnDvHeaderPacketIn: callsign='" << Header->GetMyCallsign() << "' rpt2='" << Header->GetRpt2Callsign() << "' streamId=" << Header->GetStreamId() << " from IP='" << Ip << "'" << std::endl;
    }

    // Route the header packet to all connected DExtra clients except the sender
    CClients *clients = g_Reflector.GetClients();
    int index = -1;
    CClient *client = NULL;
    while ((client = clients->FindNextClient(Header->GetMyCallsign(), Ip, PROTOCOL_DEXTRA, &index)) != NULL) {
        // Only forward to clients that are not the sender
        if (client->GetIp() != Ip) {
            CBuffer buffer;
            EncodeDvHeaderPacket(*Header, &buffer);
            client->Send(buffer);
            {
                std::lock_guard<std::mutex> lock(m_logMutex);
                std::clog << "[DExtra][DEBUG] Forwarded DV header to client IP='" << client->GetIp() << "'" << std::endl;
            }
        }
    }
    g_Reflector.ReleaseClients();
    return true;
}
{
   Buffer->Set(GetReflectorCallsign());
}

void CDextraProtocol::EncodeConnectAckPacket(CBuffer *Buffer, int ProtRev)
{
    // Always send a 14-byte ACK: 8 (callsign) + 1 (local module) + 1 (remote module) + 1 (0) + 3 ('ACK')
    uint8 cs[8];
    memset(cs, ' ', 8);
    strncpy((char*)cs, (const char*)GetReflectorCallsign(), 8);
    Buffer->clear();
    Buffer->Append(cs, 8);
    // Use the same module order as the connect packet
    if (Buffer->size() < 10) {
        Buffer->Append((uint8)'A'); // fallback
        Buffer->Append((uint8)'A');
    }
    else {
        Buffer->Append((uint8)(Buffer->data()[8]));
        Buffer->Append((uint8)(Buffer->data()[9]));
    }
    Buffer->Append((uint8)0);
    Buffer->Append((uint8)'A');
    Buffer->Append((uint8)'C');
    Buffer->Append((uint8)'K');
}

void CDextraProtocol::EncodeConnectNackPacket(CBuffer *Buffer)
{
    uint8 tag[] = { 'N','A','K',0 };
    Buffer->resize(Buffer->size()-1);
    Buffer->Append(tag, sizeof(tag));
}

void CDextraProtocol::EncodeDisconnectPacket(CBuffer *Buffer)
{
    uint8 tag[] = { ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',0 };
    Buffer->Set(tag, sizeof(tag));
}

void CDextraProtocol::EncodeDisconnectedPacket(CBuffer *Buffer)
{
    uint8 tag[] = { 'D','I','S','C','O','N','N','E','C','T','E','D' };
    Buffer->Set(tag, sizeof(tag));
}

bool CDextraProtocol::EncodeDvHeaderPacket(const CDvHeaderPacket &Packet, CBuffer *Buffer) const
{
    uint8 tag[]	= { 'D','S','V','T',0x10,0x00,0x00,0x00,0x20,0x00,0x01,0x02 };
    struct dstar_header DstarHeader;
    
    Packet.ConvertToDstarStruct(&DstarHeader);
    
    Buffer->Set(tag, sizeof(tag));
    Buffer->Append(Packet.GetStreamId());
    Buffer->Append((uint8)0x80);
    Buffer->Append((uint8 *)&DstarHeader, sizeof(struct dstar_header));
    
    return true;
}

bool CDextraProtocol::EncodeDvFramePacket(const CDvFramePacket &Packet, CBuffer *Buffer) const
{
    uint8 tag[] = { 'D','S','V','T',0x20,0x00,0x00,0x00,0x20,0x00,0x01,0x02 };
    
    Buffer->Set(tag, sizeof(tag));
    Buffer->Append(Packet.GetStreamId());
    Buffer->Append((uint8)(Packet.GetPacketId() % 21));
    Buffer->Append((uint8 *)Packet.GetAmbe(), AMBE_SIZE);
    Buffer->Append((uint8 *)Packet.GetDvData(), DVDATA_SIZE);
    
    return true;
    
}

bool CDextraProtocol::EncodeDvLastFramePacket(const CDvLastFramePacket &Packet, CBuffer *Buffer) const
{
    uint8 tag1[] = { 'D','S','V','T',0x20,0x00,0x00,0x00,0x20,0x00,0x01,0x02 };
    uint8 tag2[] = { 0x55,0xC8,0x7A,0x00,0x00,0x00,0x00,0x00,0x00,0x25,0x1A,0xC6 };
    
    Buffer->Set(tag1, sizeof(tag1));
    Buffer->Append(Packet.GetStreamId());
    Buffer->Append((uint8)((Packet.GetPacketId() % 21) | 0x40));
    Buffer->Append(tag2, sizeof(tag2));
    
    return true;
}


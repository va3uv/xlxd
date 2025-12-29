//
//  cdextraprotocol.cpp
//  xlxd
//
//  Created by Jean-Luc Deltombe (LX3JL) on 01/11/2015.
//  Copyright © 2015 Jean-Luc Deltombe (LX3JL). All rights reserved.
//
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
#include <string.h>
#include <fstream>
#include <sstream>
#include "cdextraclient.h"
#include "cdextraprotocol.h"
#include "creflector.h"
#include "cgatekeeper.h"
// Constructor/Destructor
CDextraProtocol::CDextraProtocol() : CProtocol() {
    std::clog << "[DExtra] CDextraProtocol constructor called" << std::endl;
}
CDextraProtocol::~CDextraProtocol() {}

// Load DExtra peers from config file
void CDextraProtocol::LoadDExtraPeers(const std::string& filename) {
    m_DExtraPeers.clear();
    std::clog << "[DExtra] Loading DExtra peers from: " << filename << std::endl;
    std::ifstream infile(filename);
    std::string line;
    int lineNum = 0;
    while (std::getline(infile, line)) {
        lineNum++;
        std::clog << "[DExtra] Read line " << lineNum << ": '" << line << "'" << std::endl;
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (line.empty() || line[0] == '#') {
            std::clog << "[DExtra] Skipped empty/comment line " << lineNum << std::endl;
            continue;
        }
        std::istringstream iss(line);
        std::string typeOrCallsign, ip, modules;
        if (!(iss >> typeOrCallsign >> ip >> modules)) {
            std::clog << "[DExtra] Malformed line " << lineNum << ": '" << line << "'" << std::endl;
            continue;
        }
        if (modules.length() < 2) {
            std::clog << "[DExtra] Invalid modules field on line " << lineNum << ": '" << modules << "'" << std::endl;
            continue;
        }
        DExtraPeerConfig peer;
        peer.remoteIp = ip;
        peer.localModule = modules[0];
        peer.remoteModule = modules[1];
        if (typeOrCallsign.substr(0,3) == "XRF") {
            peer.type = PEER_DEXTRA;
            peer.remoteCallsign = typeOrCallsign;
            std::clog << "[Config] Parsed DExtra peer: " << peer.remoteCallsign << " " << peer.remoteIp << " " << peer.localModule << peer.remoteModule << std::endl;
            m_DExtraPeers.push_back(peer);
        } else if (typeOrCallsign.substr(0,3) == "XLX") {
            peer.type = PEER_XLX;
            peer.remoteCallsign = typeOrCallsign;
            std::clog << "[Config] Parsed XLX peer: " << peer.remoteCallsign << " " << peer.remoteIp << " " << peer.localModule << peer.remoteModule << std::endl;
            m_DExtraPeers.push_back(peer);
        } else {
            std::clog << "[DExtra] Skipped unknown peer type on line " << lineNum << ": '" << typeOrCallsign << "'" << std::endl;
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
    std::clog << "[DExtra] PeerWithConfiguredXLX() called, " << m_DExtraPeers.size() << " peers configured" << std::endl;
    for (const auto& peer : m_DExtraPeers) {
        CIp remoteIp(peer.remoteIp.c_str());
        if (peer.type == PEER_DEXTRA) {
            CBuffer connectPacket;
            EncodeConnectPacket(localCallsign, peer.localModule, peer.remoteCallsign, peer.remoteModule, &connectPacket);
            std::clog << "[DEBUG] Sending DExtra connect to " << peer.remoteCallsign << " at " << peer.remoteIp << ":" << DEXTRA_PORT << std::endl;
            m_Socket.Send(connectPacket, remoteIp, DEXTRA_PORT);
            std::cout << "[DExtra] Sent connect to " << peer.remoteCallsign << " at " << peer.remoteIp << ":" << DEXTRA_PORT << " (local module " << peer.localModule << ", remote module " << peer.remoteModule << ")" << std::endl;
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

    // Periodically peer with configured XLX reflectors (every 10 seconds)
    if (m_LastPeerTime.DurationSinceNow() > 10) {
        PeerWithConfiguredXLX();
        m_LastPeerTime.Now();
    }

    // any incoming packet ?
    if ( m_Socket.Receive(&Buffer, &Ip, 20) != -1 )
    {
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
            uint8 ackType = Buffer.data()[11];
            std::string ackStr;
            if (memcmp(Buffer.data() + 11, "ACK", 3) == 0) ackStr = "ACK";
            else if (memcmp(Buffer.data() + 11, "NAK", 3) == 0) ackStr = "NAK";
            else ackStr = "UNKNOWN";
            std::clog << "[DExtra] Received handshake/ack packet from " << callsign << " at " << Ip << " (local module " << localModule << ", remote module " << remoteModule << ", type: " << ackStr << ")" << std::endl;
            std::clog << "[DExtra] Raw packet: ";
            for (size_t i = 0; i < Buffer.size(); ++i) {
                std::clog << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)Buffer.data()[i] << " ";
            }
            std::clog << std::dec << std::endl;
            if (ackStr == "ACK") {
                // Add a client for this remote if not already present
                CClients *clients = g_Reflector.GetClients();
                if (clients->FindClient(Ip, PROTOCOL_DEXTRA) == NULL) {
                    CDextraClient *client = new CDextraClient(CCallsign(callsign), Ip, localModule, 2);
                    clients->AddClient(client);
                    std::clog << "[DExtra] Added CDextraClient for " << callsign << " at " << Ip << std::endl;
                }
                g_Reflector.ReleaseClients();
            }
        }
            else if ( IsValidConnectPacket(Buffer, &Callsign, &ToLinkModule, &ProtRev) )
            {
                std::cout << "DExtra connect packet for module " << ToLinkModule << " from " << Callsign << " at " << Ip << " rev " << ProtRev << std::endl;
                // Only respond with ACK/NAK, do not send another connect
                if ( g_GateKeeper.MayLink(Callsign, Ip, PROTOCOL_DEXTRA) )
                {
                    if ( g_Reflector.IsValidModule(ToLinkModule) )
                    {
                        EncodeConnectAckPacket(&Buffer, ProtRev);
                        m_Socket.Send(Buffer, Ip);
                        // Add client if not already present
                        CClients *clients = g_Reflector.GetClients();
                        if (clients->FindClient(Ip, PROTOCOL_DEXTRA) == NULL) {
                            CDextraClient *client = new CDextraClient(Callsign, Ip, ToLinkModule, ProtRev);
                            clients->AddClient(client);
                        }
                        g_Reflector.ReleaseClients();
                    }
                    else
                    {
                        std::cout << "DExtra node " << Callsign << " connect attempt on non-existing module" << std::endl;
                        EncodeConnectNackPacket(&Buffer);
                        m_Socket.Send(Buffer, Ip);
                    }
                }
                else
                {
                    EncodeConnectNackPacket(&Buffer);
                    m_Socket.Send(Buffer, Ip);
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
                CClients *clients = g_Reflector.GetClients();
                int index = -1;
                CClient *client = NULL;
                while ( (client = clients->FindNextClient(Callsign, Ip, PROTOCOL_DEXTRA, &index)) != NULL )
                {
                   client->Alive();
                }
                g_Reflector.ReleaseClients();
            }
            else
            {
                std::cout << "DExtra packet (" << Buffer.size() << ")" << std::endl;
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
// keepalive helpers

void CDextraProtocol::HandleKeepalives(void)
{
    // DExtra protocol sends and monitors keepalives packets
    // event if the client is currently streaming
    // so, send keepalives to all
    CBuffer keepalive;
    EncodeKeepAlivePacket(&keepalive);
    
    // iterate on clients
    CClients *clients = g_Reflector.GetClients();
    int index = -1;
    CClient *client = NULL;
    while ( (client = clients->FindNextClient(PROTOCOL_DEXTRA, &index)) != NULL )
    {
        // send keepalive
        m_Socket.Send(keepalive, client->GetIp());
        
        // client busy ?
        if ( client->IsAMaster() )
        {
            // yes, just tickle it
            client->Alive();
        }
        // otherwise check if still with us
        else if ( !client->IsAlive() )
        {
            // no, disconnect
            CBuffer disconnect;
            EncodeDisconnectPacket(&disconnect);
            m_Socket.Send(disconnect, client->GetIp());
            
            // remove it
            std::cout << "DExtra client " << client->GetCallsign() << " keepalive timeout" << std::endl;
            clients->RemoveClient(client);
        }
        
    }
    g_Reflector.ReleaseClients();
}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

bool CDextraProtocol::OnDvHeaderPacketIn(CDvHeaderPacket *Header, const CIp &Ip)
{
    bool newstream = false;
    
    // find the stream
    CPacketStream *stream = GetStream(Header->GetStreamId());
    if ( stream == NULL )
    {
        // no stream open yet, open a new one
        CCallsign via(Header->GetRpt1Callsign());
        
        // find this client
        CClient *client = g_Reflector.GetClients()->FindClient(Ip, PROTOCOL_DEXTRA);
        if ( client != NULL )
        {
            // get client callsign
            via = client->GetCallsign();
            // apply protocol revision details
            if ( client->GetProtocolRevision() == 2 )
            {
                // update Header RPT2 module letter with
                // the module the client is linked to
                Header->SetRpt2Module(client->GetReflectorModule());
            }
            // and try to open the stream
            if ( (stream = g_Reflector.OpenStream(Header, client)) != NULL )
            {
                // keep the handle
                m_Streams.push_back(stream);
                newstream = true;
            }
        }
        // release
        g_Reflector.ReleaseClients();
        
        // update last heard
        g_Reflector.GetUsers()->Hearing(Header->GetMyCallsign(), via, Header->GetRpt2Callsign());
        g_Reflector.ReleaseUsers();
        
        // delete header if needed
        if ( !newstream )
        {
            delete Header;
        }
    }
    else
    {
        // stream already open
        // skip packet, but tickle the stream
        stream->Tickle();
        // and delete packet
        delete Header;
    }
    
    // done
    return newstream;
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
{
   Buffer->Set(GetReflectorCallsign());
}

void CDextraProtocol::EncodeConnectAckPacket(CBuffer *Buffer, int ProtRev)
{
   // is it for a XRF or repeater
    if ( ProtRev == 2 )
    {
        // XRFxxx
        uint8 rm = (Buffer->data())[8];
        uint8 lm = (Buffer->data())[9];
        Buffer->clear();
        Buffer->Set((uint8 *)(const char *)GetReflectorCallsign(), CALLSIGN_LEN);
        Buffer->Append(lm);
        Buffer->Append(rm);
        Buffer->Append((uint8)0);
    }
    else
    {
        // regular repeater
        uint8 tag[] = { 'A','C','K',0 };
        Buffer->resize(Buffer->size()-1);
        Buffer->Append(tag, sizeof(tag));
    }
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


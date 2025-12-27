//
//  cdextrapeer.cpp
//  xlxd
//
//  Created by Antony Chazapis (SV9OAN) on 25/2/2018.
//  Copyright © 2016 Jean-Luc Deltombe (LX3JL). All rights reserved.
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
#include "creflector.h"
#include "cdextrapeer.h"
#include "cdextraclient.h"


////////////////////////////////////////////////////////////////////////////////////////
// constructor


CDextraPeer::CDextraPeer()
{
}

CDextraPeer::CDextraPeer(const CCallsign &callsign, const CIp &ip, const char *modules, const CVersion &version)
: CPeer(callsign, ip, modules, version)
{
    std::cout << "Adding DExtra peer" << std::endl;

    // and construct the DExtra clients
    for (unsigned int i = 0; i < ::strlen(modules); i++)
    {
        // create
        CDextraClient *client = new CDextraClient(callsign, ip, modules[i], version.GetMajor());
        // and append to vector
        m_Clients.push_back(client);
    }
}

CDextraPeer::CDextraPeer(const CDextraPeer &peer)
: CPeer(peer)
{
    for (auto it = peer.m_Clients.begin(); it!=peer.m_Clients.end(); it++)
    {
        CDextraClient *client = new CDextraClient((const CDextraClient &)*(*it));
        m_Clients.push_back(client);

    }
}

////////////////////////////////////////////////////////////////////////////////////////
// destructors

CDextraPeer::~CDextraPeer()
{
}

////////////////////////////////////////////////////////////////////////////////////////
// status

bool CDextraPeer::IsAlive(void) const
{
    for (auto it=m_Clients.begin(); it!=m_Clients.end(); it++)
    {
        if (! (*it)->IsAlive())
			return false;
    }
    return true;
}

////////////////////////////////////////////////////////////////////////////////////////
// revision helper

int CDextraPeer::GetProtocolRevision(const CVersion &version)
{
    return version.GetMajor();
}


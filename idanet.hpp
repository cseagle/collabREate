/*
    Asynchronous IDA communications handler
    Copyright (C) 2008 Chris Eagle <cseagle at gmail d0t com>

    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the Free
    Software Foundation; either version 2 of the License, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along with
    this program; if not, write to the Free Software Foundation, Inc., 59 Temple
    Place, Suite 330, Boston, MA 02111-1307 USA

*/

#ifndef __IDACONNECTOR_H__
#define __IDACONNECTOR_H__

#include "buffer.h"
#include "sdk_versions.h"

typedef bool (*Dispatcher)(Buffer &b);

#ifndef __NT__
#define _SOCKET int
#define closesocket close
#else
#define _SOCKET unsigned int
#endif

#if IDA_SDK_VERSION >= 550
bool connect_to(const char *host, short port, Dispatcher d);
#else
_SOCKET connect_to(const char *host, short port);
bool createSocketWindow(_SOCKET s, Dispatcher d);
void killWindow();
#endif

#endif

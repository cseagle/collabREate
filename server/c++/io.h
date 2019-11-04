/*
   collabREate io.h
   Copyright (C) 2018 Chris Eagle <cseagle at gmail d0t com>
   Copyright (C) 2018 Tim Vidas <tvidas at gmail d0t com>

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

#ifndef __COLLAB_IO_H
#define __COLLAB_IO_H

#include <stdint.h>
#include <stdarg.h>
#include <sys/select.h>
#include <string>
#include <vector>
#include <json-c/json.h>

using std::string;
using std::vector;

struct sockaddr_in6;
class NetworkIO;

class IOException {
public:
   IOException(const string &msg = "");
   const string &getMessage();
private:
   string msg;
};

class NetworkIO {
public:
   NetworkIO() {this->fd = -1; did_ping = false;};
   NetworkIO(int fd) {this->fd = fd; did_ping = false;};
   ~NetworkIO() {close();};

   bool writeJson(json_object *obj);
   ssize_t sendMsg(const char *buf, bool nullflag = 0);
   ssize_t sendAll(const void *buf, ssize_t len);
   ssize_t sendFormat(const char *format, ...);

   json_object *readJson();
   int getPeerPort();
   string getPeerAddr();
   bool close();
protected:
   int fd;
private:
   string json_buffer;
   bool did_ping;
};

class NetworkService {
public:
   virtual ~NetworkService();
   virtual NetworkIO *accept() = 0;
   virtual bool close();
protected:
   vector<int> fds;
   fd_set aset;
   int nfds;
};

class Tcp6Service : public NetworkService {
public:
   Tcp6Service(int port);
   Tcp6Service(const char *host, int port);
   virtual ~Tcp6Service();
   NetworkIO *accept();
private:
   sockaddr_in6 *self;
};

class Tcp6IO : public NetworkIO {
public:
   Tcp6IO(int fd, sockaddr_in6 &peer);
   ~Tcp6IO();

private:
   sockaddr_in6 *peer;
};

#endif


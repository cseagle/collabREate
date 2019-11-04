/*
   collabREate io.cpp
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <stdint.h>
#include <string>
#include <openssl/md5.h>
#include <json-c/json.h>

#include "io.h"
#include "utils.h"

using std::string;

#define ERROR_CREATE_SOCK "Unable to create socket"
#define ERROR_REUSE_SOCK "Unable to set reuse"
#define ERROR_BIND_SOCK "Unable to bind socket"
#define ERROR_LISTEN_SOCK "Unable to listen on socket"

IOException::IOException(const string &msg) {
   this->msg = msg;
}
const string &IOException::getMessage() {
   return msg;
}

bool NetworkIO::writeJson(json_object *obj) {
   size_t jlen;
   const char *json = json_object_to_json_string_length(obj, JSON_C_TO_STRING_PLAIN, &jlen);
   sendMsg(json, 0);
   json_object_put(obj);   //release the object
   return true;
}

json_object *NetworkIO::readJson() {
   json_object *obj;
   uint64_t ping_val;
   while (true) {
      bool res = ::readJson(fd, json_buffer, &obj, ping_timeout);
      if (res) {
         if (obj == NULL) {
            //we really can't do anything anymore
            break;
         }
         else {
            //the client remains alive
            did_ping = false;
            const char *type = string_from_json(obj, "type");
            if (strcmp(type, "pong") == 0) {
               uint64_t val;
               bool has_id = uint64_from_json(obj, "id", &val);
               json_object_put(obj);
               if (has_id) {
                  if (ping_val != val) {
                     return NULL;
                  }
               }
               else {
                  //malformed pong
                  return NULL;
               }
            }
            else {
               //not a pong, return object to caller
               break;
            }
         }
      }
      else {
         //timed out
         if (did_ping) {
            return NULL;
         }
         //send a ping to see if they are alive
         char ping[256];
         fill_random((unsigned char*)&ping_val, sizeof(ping_val));
         ping_val &= 0x7fffffffffffffff;  //make sure it's >= 0
         snprintf(ping, sizeof(ping), "{\"type\":\"ping\",\"id\":%llu}", (long long unsigned int)ping_val);
         did_ping = true;
         sendMsg(ping);
      }
   }
   return obj;
}

Tcp6IO::Tcp6IO(int fd, sockaddr_in6 &peer) {
   this->peer = new sockaddr_in6(peer);
   this->fd = fd;
}

Tcp6IO::~Tcp6IO() {
   delete peer;
}

int NetworkIO::getPeerPort() {
   sockaddr_in sa;
   socklen_t slen = sizeof(sa);
   getpeername(fd, (sockaddr*)&sa, &slen);
   return htons(sa.sin_port);
}

string NetworkIO::getPeerAddr() {
   sockaddr_in6 sa6;
   sockaddr_in *sa4 = (sockaddr_in*)&sa6;
   const char *res = NULL;
   socklen_t slen = sizeof(sa6);
   char addr[INET6_ADDRSTRLEN];
   getpeername(fd, (sockaddr*)&sa6, &slen);
   if (sa6.sin6_family == AF_INET6) {
      res = inet_ntop(AF_INET6, &sa6.sin6_addr, addr, INET6_ADDRSTRLEN);
   }
   else if (sa4->sin_family == AF_INET) {
      res = inet_ntop(AF_INET, &sa4->sin_addr, addr, INET6_ADDRSTRLEN);
   }
   if (res) {
      return addr;
   }
   return "???";
}

/*
 * Write the string contained in buf to the client socket
 * strlen is used to compute the length of buf.  If nullflag
 * is non-zero, then the null terminator is also written to
 * the client.
 */
ssize_t NetworkIO::sendMsg(const char *buf, bool nullflag) {
   size_t len = strlen(buf);
   return sendAll((const unsigned char *)buf, nullflag ? (len + 1) : len);
}

/*
 * write size characters from buf to the client socket
 * returns -1 on error or size if all chars were
 * written.
 */
ssize_t NetworkIO::sendAll(const void *buf, ssize_t size) {
   ssize_t total = 0;
   const unsigned char *b = (const unsigned char *)buf;
   while (total < size) {
      ssize_t nbytes = ::write(fd, b + total, size - total);
      if (nbytes == 0) return -1;
      total += nbytes;
   }
   return total;
}

ssize_t NetworkIO::sendFormat(const char *format, ...) {
   ssize_t result = 0;
   char *ptr = NULL;
   va_list argp;
   va_start(argp, format);
   if (vasprintf(&ptr, format, argp) == -1 || ptr == NULL) {
      result = -1;
   }
   else {
      result = sendMsg(ptr, 0);
   }
   free(ptr);
   va_end(argp);
   return result;
}

/*
 * setup the server socket by binding to 0.0.0.0:port
 * SO_REUSEADDR is set on the socket.
 * returns the new server socket.
 */
Tcp6Service::Tcp6Service(int port) {
   int server = socket(AF_INET6, SOCK_STREAM, 0);
   if (server == -1) {
#ifdef DEBUG
      err(-1, ERROR_CREATE_SOCK);
#else
      throw -1;
#endif
   }
   int one = 1;
   if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
      close();
#ifdef DEBUG
      err(-1, ERROR_REUSE_SOCK);
#else
      throw -1;
#endif
   }
   self = new sockaddr_in6;
//   struct sockaddr_in6 my_addr = IN6ADDR_ANY_INIT;
   memset(self, 0, sizeof(*self));
   self->sin6_family = AF_INET6;
   self->sin6_port = htons(port);
   if (bind(server, (struct sockaddr*)self, sizeof(*self)) == -1) {
      close();
      delete self;
#ifdef DEBUG
      err(-1, ERROR_BIND_SOCK);
#else
      throw -1;
#endif
   }
   if (listen(server, 20) == -1) {
      close();
      delete self;
#ifdef DEBUG
      err(-1, ERROR_LISTEN_SOCK);
#else
      throw -1;
#endif
   }
   fds.push_back(server);
   nfds = server + 1;
}

/*
 * setup the server socket by binding to host:port
 * SO_REUSEADDR is set on the socket.
 * returns the new server socket.
 */
Tcp6Service::Tcp6Service(const char *host, int port) {
   char str_port[16];
   struct addrinfo hints;
   addrinfo *addr, *ap;
   int one = 1;
   nfds = 0;
   FD_ZERO(&aset);

   snprintf(str_port, sizeof(str_port), "%d", port);
   memset(&hints, 0, sizeof(addrinfo));
   hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
   hints.ai_socktype = SOCK_STREAM; /* Stream socket */
   hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
   hints.ai_protocol = 0;          /* Any protocol */
   hints.ai_canonname = NULL;
   hints.ai_addr = NULL;
   hints.ai_next = NULL;

   if (getaddrinfo(host, str_port, &hints, &addr) != 0) {
      throw IOException("Failed to getaddrinfo");
   }

   for (ap = addr; ap != NULL; ap = ap->ai_next) {
      int fd = socket(ap->ai_family, ap->ai_socktype, ap->ai_protocol);
      if (fd == -1) {
         continue;
      }
      if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
         ::close(fd);
         continue;
      }
      if (bind(fd, ap->ai_addr, ap->ai_addrlen) != 0) {
         ::close(fd);
         continue;
      }
      if (listen(fd, 20) == -1) {
         ::close(fd);
         continue;
      }
      if (nfds <= fd) {
         nfds = fd + 1;
      }
      fds.push_back(fd);
   }

   freeaddrinfo(addr);

   if (fds.size() == 0) {
#ifdef DEBUG
      err(-1, ERROR_CREATE_SOCK);
#else
      throw -1;
#endif
   }

}

bool NetworkIO::close() {
   return ::close(fd) == 0;
}

NetworkService::~NetworkService() {
   close();
}

bool NetworkService::close() {
   int res = 0;
   for (vector<int>::iterator i = fds.begin(); i != fds.end(); i++) {
      res |= ::close(*i);
   }
   return res == 0;
}

Tcp6Service::~Tcp6Service() {
   delete self;
}

NetworkIO *Tcp6Service::accept() {
   FD_ZERO(&aset);
   for (vector<int>::iterator i = fds.begin(); i != fds.end(); i++) {
      FD_SET(*i, &aset);
   }
   //inifinite wait in select
   if (select(nfds, &aset, NULL, NULL, NULL) > 0) {
      for (vector<int>::iterator i = fds.begin(); i != fds.end(); i++) {
         if (FD_ISSET(*i, &aset)) {
            struct sockaddr_in6 peer;
            socklen_t peer_len = sizeof(peer);
            int client = ::accept(*i, (struct sockaddr*)&peer, &peer_len);
            if (client != -1) {
               return new Tcp6IO(client, peer);
            }
         }
      }
   }
   return NULL;
}

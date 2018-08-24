/*
    Asynchronous IDA communications handler
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

#ifdef _WIN32
#ifndef _MSC_VER
#include <windows.h>
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <pro.h>

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <md5.h>
#include <stdint.h>

#include <json-c/json.h>

#include "collabreate.h"
#include "idanet.h"

//array to track send and receive stats for all of the collabreate commands
extern int stats[2][MSG_IDA_MAX + 1];

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>

#define closesocket close
#define INVALID_SOCKET ((_SOCKET)-1)
#define SOCKET_ERROR -1
#endif

struct disp_request_t : public exec_request_t {
   disp_request_t(Dispatcher disp) : _disp(disp) {mtx = qmutex_create();};
   ~disp_request_t();
   virtual int idaapi execute(void);

   //disp_requst_t takes ownership of the buffer
   //it will be deleted eventually in execute
   void queueObject(json_object *obj);

   void flush(void);

   qvector<json_object*> objects;
   qmutex_t mtx;
   Dispatcher _disp;
};

class CollabSocket {
public:
   CollabSocket(Dispatcher disp);
   bool isConnected();
   bool connect(const char *host, short port);
   bool close();
   void cleanup(bool warn = false);
   bool sendAll(const qstring &s);
   bool sendMsg(const qstring &s);
   int recv(unsigned char *buf, unsigned int len);
private:
#ifdef _WIN32
   HANDLE thread;
   static DWORD WINAPI recvHandler(void *sock);
#else
   pthread_t thread;
   static void *recvHandler(void *sock);
#endif
   qstring host;
   short port;
   Dispatcher _disp;
   disp_request_t *drt;
   _SOCKET conn;
   bool connected;
   static bool initNetwork();
};

static CollabSocket *comm;

bool init_network() {
   static bool isInit = false;
   if (!isInit) {
#ifdef _WIN32
   //initialize winsock.
      WSADATA wsock;
      if (WSAStartup(MAKEWORD(2, 2), &wsock) != 0) {
         msg(PLUGIN_NAME": initNetwork() failed.\n");
      }
      //check requested version
      else if (LOBYTE(wsock.wVersion) != 2 || HIBYTE(wsock.wVersion) != 2) {
//         WSACleanup();
         msg(PLUGIN_NAME": Winsock version 2.2 not found.\n");
      }
      else {
         isInit = true;
      }
#else
      isInit = true;
#endif

   }
   return isInit;
}

//connect to a remote host as specified by host and port
//host may be either an ip address or a host name
bool connect_to(const char *host, short port, _SOCKET *sock) {

   bool result = false;

   addrinfo hints;
   addrinfo *ai;
   sockaddr_in *server;
   
   memset(&hints, 0, sizeof(addrinfo));
   hints.ai_family = AF_INET;
   hints.ai_socktype = SOCK_STREAM;

   if (getaddrinfo(host, NULL, &hints, &ai) == 0) {

      server = (sockaddr_in*)ai->ai_addr;
      server->sin_port = qhtons(port);
   
      //create a socket.
      if ((*sock = (_SOCKET)socket(AF_INET, SOCK_STREAM, 0)) != INVALID_SOCKET) {
         if (connect(*sock, ai->ai_addr, (int)ai->ai_addrlen) == SOCKET_ERROR) {
            msg(PLUGIN_NAME": Failed to connect to server.\n");
            closesocket(*sock);
         }
         else {
#ifdef _WIN32
            DWORD tv = 2000;
#else
            timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0;
#endif
            //we force a periodic timeout to force a recv error after
            //the socket has been closed. On windows, simply closing 
            //the socket causes a blocking recv to fail and the recvHandler
            //thread to terminate. On Linux, closing the socket was not
            //causing the blocking recv to terminate, hence the timeout
            //following a timeout, if the socket has been closed, the next
            //receive will fail. Not elegant but it works
            setsockopt(*sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
            result = true;
         }
      }
      else {
         msg(PLUGIN_NAME": Failed to create socket.\n");
      }
      freeaddrinfo(ai);
   }      
   return result;
}

disp_request_t::~disp_request_t() {
   flush();
   qmutex_free(mtx);
};

//this is the callback that gets called by execute_sync, in theory new datagrams
//can arrive and be processed during the loop since queue synchronization takes
//place within the StringList
int idaapi disp_request_t::execute(void) {
//   msg("execute called\n");
   while (objects.size() > 0) {
      qmutex_lock(mtx);
      qvector<json_object*>::iterator i = objects.begin();
      json_object *obj = *i;
      objects.erase(i);
      qmutex_unlock(mtx);
//      msg("dequeued: %s\n", s->c_str());
      bool res = (*_disp)(obj);
      if (!res) {  //not sure we really care what is returned here
//         msg(PLUGIN_NAME": connection to server severed at dispatch.\n");
         comm->cleanup(true);
         break;
      }
      else {
         //msg(PLUGIN_NAME": dispatch routine called successfully.\n");
      }
   }
   return 0;
}

//queue up a received datagram for eventual handlng via IDA's execute_sync mechanism
//call no sdk functions other than execute_sync
void disp_request_t::queueObject(json_object *obj) {
   bool call_exec = false;
   qmutex_lock(mtx);
   objects.push_back(obj);
   call_exec = objects.size() == 1;
   qmutex_unlock(mtx);

   if (call_exec) {
      //only invoke execute_sync if the buffer just added was at the head of the queue
      //in theory this allows multiple datagrams to get queued for handling
      //in a single execute_sync callback
      execute_sync(*this, MFF_WRITE);
   }
}

void disp_request_t::flush() {
   qmutex_lock(mtx);
   for (qvector<json_object*>::iterator i = objects.begin(); i != objects.end(); i++) {
      json_object_put(*i);
   }
   objects.clear();
   qmutex_unlock(mtx);
}

bool connect_to(const char *host, short port, Dispatcher disp) {
   comm = new CollabSocket(disp);
   if (!comm->connect(host, port)) {
      delete comm;
      comm = NULL;
   }
   return comm != NULL;
}

bool is_connected() {
   return comm != NULL ? comm->isConnected() : false;
}

bool CollabSocket::isConnected() {
   return connected;
}

/////////////////////////////////////////////////////////////////////////////////////////
//cleanup(bool warn)
//
//cancel all notifications, close the socket and destroy the hook notification window.
//
//arguments: warn true displays a warning that cleanup is being called, false no warning
//returns:   none.
//
void CollabSocket::cleanup(bool warn) {
   //cancel all notifications. if we don't do this ida will crash on exit.
   msg(PLUGIN_NAME": cleanup called.\n");
   if (connected) {
      int res = ::closesocket(conn);
      msg("closesocket returned %d\n", res);
      connected = false;
      conn = (_SOCKET)INVALID_SOCKET;
#ifdef _WIN32
      if (thread) {
         msg("attempting to sync on thread exit\n");
         WaitForSingleObject(thread, INFINITE);
         thread = NULL;
      }
#else
      if (thread) {
         msg("attempting to sync on thread exit\n");
         pthread_join(thread, NULL);
         thread = 0;
      }
#endif
      if (warn) {
         warning("Connection to collabREate server has been closed.\n"
                 "You should reconnect to the server before sending\n"
                 "additional updates.");
      }
   }
}

/////////////////////////////////////////////////////////////////////////////////////////
//cleanup(bool warn)
//
//cancel all notifications, close the socket and destroy the hook notification window.
//
//arguments: warn true displays a warning that cleanup is being called, false no warning
//returns:   none.
//
void cleanup(bool warn) {
   if (comm) {
      comm->cleanup(warn);
      delete comm;
      comm = NULL;
   }
}

//connect to a remote host as specified by host and port
//host may be wither an ip address or a host name
bool CollabSocket::connect(const char *host, short port) {
   //create a socket.
   //remember these values if we need to reconnect
   this->host = host;
   this->port = port;
   if (connect_to(host, port, &conn)) {
      //socket is connected create thread to handle receive data
#ifdef _WIN32
      if ((thread = CreateThread(NULL, 0, recvHandler, this, 0, NULL)) == NULL) {
#else
      if (pthread_create(&thread, NULL, recvHandler, this)) {
#endif
         //error failed to create thread
         msg(PLUGIN_NAME": Failed to create connection handler.\n");
         cleanup();
      }
      else {
         connected = true;
      }
   }
   else {
      msg(PLUGIN_NAME": Failed to create socket.\n");
   }
   return connected;
}

bool CollabSocket::sendAll(const qstring &s) {
   qstring buf = s;
   while (true) {
//      msg("sending new buffer\n");
      int len = ::send(conn, buf.c_str(), (int)buf.length(), 0);
      if (len == (int)buf.length()) {
         break;
      }
      if (len == SOCKET_ERROR) {
#ifdef _WIN32
         int sockerr = WSAGetLastError();
#else
         int sockerr = errno;
#endif
         cleanup();
         msg(PLUGIN_NAME": Failed to send requested data. %d != %d. Error: 0x%x(%d)\n", len, buf.length(), sockerr, sockerr);
         return false;
      }
      else if (len != (int)buf.length()) {
         //shift the remainder and try again
         buf = buf.c_str() + len;
         //msg(PLUGIN_NAME": Short send. %d != %d.", len, out.size());
      }
   }
   return true;
}

CollabSocket::CollabSocket(Dispatcher disp) {
   _disp = disp;
   thread = 0;
   init_network();
   conn = (_SOCKET)INVALID_SOCKET;
   connected = false;
   drt = new disp_request_t(_disp);
}

bool CollabSocket::close() {
   cleanup();
   return true;
}

int CollabSocket::recv(unsigned char *buf, unsigned int len) {
   return ::recv(conn, (char*)buf, len, 0);
}

//We don't call ANY sdk functions from here because this is a separate thread
//and we don't want to do anything other than execute_sync (which happens in
//queueBuffer
#ifdef _WIN32
DWORD WINAPI CollabSocket::recvHandler(void *_sock) {
#else
void *CollabSocket::recvHandler(void *_sock) {
#endif
   static qstring b;
   unsigned char buf[2048];  //read a large chunk, we'll be notified if there is more
   CollabSocket *sock = (CollabSocket*)_sock;
   json_tokener *tok = json_tokener_new();

   while (sock->isConnected()) {
      int len = sock->recv(buf, sizeof(buf) - 1);
      if (len <= 0) {
#ifdef _WIN32
         //timeouts are okay
         if (WSAGetLastError() == WSAETIMEDOUT) {
            continue;
         }
#else
         //timeouts are okay
         if (errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
         }
#endif
//       assumption is that socket is borked and next send will fail also
//       maybe should close socket here at a minimum.
//       in any case thread is exiting
//       reconnecting is a better strategy
         break;
      }
      if (sock->_disp) {
         json_object *jobj = NULL;
         enum json_tokener_error jerr;
         buf[len] = 0;
         b.append((char*)buf, len);   //append new data into static buffer

         while (1) {
            jobj = json_tokener_parse_ex(tok, b.c_str(), b.length());
            jerr = json_tokener_get_error(tok);
            if (jerr == json_tokener_continue) {
               //json object is syntactically correct, but incomplete
//               msg("json_tokener_continue for %s\n", b.c_str());
               break;
            }
            else if (jerr != json_tokener_success) {
               //need to reconnect socket and in the meantime start caching event locally
//               msg("jerr != json_tokener_success for %s\n", b.c_str());
               break;
            }
            else if (jobj != NULL) {
               //we extracted a json object from the front of the string
               //queue it and trim the string
//               msg("json_tokener_success for %s\n", b.c_str());
               if (tok->char_offset < b.length()) {
                  //shift any remaining portions of the buffer to the front
                  b.remove(0, tok->char_offset); 
               }
               else {
                  b.clear();
               }
               sock->drt->queueObject(jobj);
            }
         }
         json_tokener_reset(tok);
      }
   }
   json_tokener_free(tok);
   return 0;
}

int send_all(const qstring &s) {
   if (comm) {
      return comm->sendAll(s);
   }
   return 0;
}

int send_msg(const qstring &s) {
   if (comm) {
      return comm->sendAll(s);
   }
   else {
      if (changeCache != NULL) {
//         msg("writing to change cache\n");
         *changeCache += s;
         return (int)s.length();
      }
   }
   return 0;
}

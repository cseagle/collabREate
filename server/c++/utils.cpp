/*
   collabREate utils.cpp
   Copyright (C) 2012 Chris Eagle <cseagle at gmail d0t com>
   Copyright (C) 2012 Tim Vidas <tvidas at gmail d0t com>

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
#include <err.h>
#include <stdint.h>
#include <string>
#include <openssl/md5.h>

#include "buffer.h"
#include "utils.h"

#define ERROR_CREATE_SOCK "Unable to create socket"
#define ERROR_REUSE_SOCK "Unable to set reuse"
#define ERROR_BIND_SOCK "Unable to bind socket"
#define ERROR_LISTEN_SOCK "Unable to listen on socket"

const char *permStrings[] = {
      "Undefine",
      "Make Code",
      "Make Data",
      "Segments",
      "Renames",
      "Functions",
      "Byte Patch",
      "Comments",
      "Optypes",
      "Enums",
      "Structs",
      "Flirt",
      "Thunk",
      "Xrefs",
      NULL
};

int permStringsLength = sizeof(permStrings) / sizeof(char*) - 1;

union uLongLong {
   uint64_t ll;
   uint32_t ii[2];
};

uint64_t htonll(uint64_t val) {
   uLongLong ull;
   ull.ll = val;
   uint32_t t = ull.ii[0];
   ull.ii[0] = htonl(ull.ii[1]);
   ull.ii[1] = htonl(t);
   return ull.ll;
}

/**
 * toByteArray - generate a byte array representation of the specified
 *               string
 * @param hexString The string to convert
 * @return The byte array representation of the given string
 */
uint8_t *toByteArray(string hexString) {
   if ((hexString.length() % 2) == 1) {
      //invalid hex string
      return NULL;
   }
   int idx = 0;
   uint8_t *result = new uint8_t[hexString.length() / 2];
   const char *hbuf = hexString.c_str();
   for (int i = 0; i < hexString.length(); i += 2) {
      char buf[4];
      memcpy(buf, hbuf + i, 2);
      buf[2] = 0;
      uint32_t val;
      sscanf(buf, "%x", &val);
      result[idx++] = (uint8_t)val;
   }
   return result;
}

/**
 * tests if the provided string contains digits only
 * @param s string to test
 */
bool isNumeric(string s) {
   if (s.length() == 0) {
      return false;
   }
   for (int i = 0; i < s.length(); i++) {
      if (!isdigit(s.at(i))) {
         return false;
      }
   }
   return true;
}

/**
 * tests if the provided string contains hex characters only
 * @param s string to test
 */
bool isHex(string s) {
   if (s.length() == 0) {
      return false;
   }
   for (int i = 0; i < s.length(); i++) {
      if (!isxdigit(s.at(i))) {
         return false;
      }
   }
   return true;
}

/**
 * tests if the provided string contains letters and digits only
 * @param s string to test
 */
bool isAlphaNumeric(string s) {
   if (s.length() == 0) {
      return false;
   }
   for (int i = 0; i < s.length(); i++) {
      if (!isalnum(s.at(i))) {
         return false;
      }
   }
   return true;
}

string toHexString(const uint8_t *buf, int len) {
   char hex[16];
   string res = "";
   for (int i = 0; i < len; i++) {
      snprintf(hex, sizeof(hex), "%02x", buf[i]);
      res += hex;
   }
   return res;
}

/**
 * getMD5 - calculate the md5sum of a string 
 * @param tohash The string to hash 
 * @return The md5sum of the input string 
 */
string getMD5(const void *tohash, int len) {
   string hashString = "";
   uint8_t digest[MD5_DIGEST_LENGTH];
   MD5((const unsigned char *)tohash, len, digest);
   hashString = toHexString(digest, MD5_DIGEST_LENGTH);
   return hashString;
}

string getMD5(const string &s) {
   return getMD5(s.c_str(), s.length());
}

void log(const string &msg , int verbosity) {
   fprintf(stderr, "%s\n", msg.c_str());
}

void logln(const string &msg , int verbosity) {
   log(msg + "\n", verbosity);
}

IOException::IOException(const string &msg) {
   this->msg = msg;
}
const string &IOException::getMessage() {
   return msg;
}

IOBase &FileIO::operator<<(const string &s) {
   this->sendMsg(s.c_str(), 0);
   return *this;
}

IOBase &FileIO::operator<<(const Buffer &b) {
   this->sendAll(b.get_buf(), b.size());
   return *this;
}

IOBase &FileIO::operator>>(Buffer &b) {
   int res = this->readAll(b.get_buf(), b.capacity());
   if (res >= 0) {
      b.seek(res);
   }
   return *this;
}

Tcp6IO::Tcp6IO(int fd, sockaddr_in6 &peer) {
   this->peer = new sockaddr_in6(peer);
   this->fd = fd;
}

Tcp6IO::~Tcp6IO() {
   delete peer;
}

void FileIO::setFileDescriptor(int fd) {
   this->fd = fd;
}

/*
 * This reads up to size bytes into a user supplied buffer
 * Returns the number of bytes read or -1 if size bytes
 * could not be read.
 * This function is really only useful for reading fixed 
 * size fields.
 */
int FileIO::readAll(void *buf, unsigned int size) {
   unsigned int total = 0;
   unsigned char *b = (unsigned char *)buf;
   int nbytes;
   while (total < size) {
      nbytes = read(fd, b + total, size - total);
      if (nbytes <= 0) {
         return -1;
      }
      total += nbytes;
   }
   return (int)total;
}

/*
 * This reads up to size bytes into a user supplied buffer
 * Returns the number of bytes read or -1 if size bytes
 * could not be read.
 * This function is really only useful for reading fixed 
 * size fields.
 */
int NetworkIO::readAll(void *buf, unsigned int size) {
   unsigned int total = 0;
   unsigned char *b = (unsigned char *)buf;
   int nbytes;
   while (total < size) {
      nbytes = recv(fd, b + total, size - total, 0);
      if (nbytes <= 0) {
         return -1;
      }
      total += nbytes;
   }
   return (int)total;
}

/*
 * Read characters into buf until endchar is found. Stop reading when
 * endchar is read.  Returns the total number of chars read EXCLUDING
 * endchar.  endchar is NEVER copied into the buffer.  Note that it
 * is possible to perform size+1 reads as long as the last char read
 * is endchar.
 */
int FileIO::read_until_delim(char *buf, unsigned int size, char endchar) {
   char ch;
   unsigned int total = 0;
   while (1) {
      if (read(fd, &ch, 1) <= 0) {
         return -1;
      }
      if (ch == endchar) break;
      if (total >= size) return -1;
      buf[total++] = ch;
   }
   return (int)total;
}

bool FileIO::readLine(Buffer &b) {
   unsigned char ch;
   while (read(fd, &ch, 1) == 1) {
      if (ch == '\n') {
         return true;
      }
      if (!b.write(ch)) {
         return false;
      }
   }
   return false;
}

string FileIO::readLine() {
   unsigned char ch;
   string res;
   while (read(fd, &ch, 1) == 1) {
      res += ch;
      if (ch == '\n') {
         break;
      }
   }
   return res;
}

NetworkIO::NetworkIO(const char *host, int port) {
   struct addrinfo hints;
   addrinfo *addr, *ap;
   char str_port[16];
   
   memset(&hints, 0, sizeof(addrinfo));
   hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
   hints.ai_socktype = SOCK_STREAM; /* Stream socket */
   hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
   hints.ai_protocol = 0;          /* Any protocol */
   hints.ai_canonname = NULL;
   hints.ai_addr = NULL;
   hints.ai_next = NULL;
   
   snprintf(str_port, sizeof(str_port), "%d", port);
              
   if (getaddrinfo(host, str_port, &hints, &addr) != 0) {
      throw IOException();
   }

   for (ap = addr; ap != NULL; ap = ap->ai_next) {
      fd = socket(ap->ai_family, ap->ai_socktype, ap->ai_protocol);
      if (fd == -1) {
         continue;
      }
      
      if (connect(fd, ap->ai_addr, ap->ai_addrlen) == 0) {
         break;
      }
      
      ::close(fd);
   }
   
   if (ap == NULL) {
      throw IOException();
   }

   freeaddrinfo(addr);
}

/*
 * Read characters into buf until endchar is found. Stop reading when
 * endchar is read.  Returns the total number of chars read EXCLUDING
 * endchar.  endchar is NEVER copied into the buffer.  Note that it
 * is possible to perform size+1 reads as long as the last char read
 * is endchar.
 */
int NetworkIO::read_until_delim(char *buf, unsigned int size, char endchar) {
   char ch;
   unsigned int total = 0;
   while (1) {
      if (recv(fd, &ch, 1, 0) <= 0) {
         return -1;
      }
      if (ch == endchar) break;
      if (total >= size) return -1;
      buf[total++] = ch;
   }
   return (int)total;
}

bool NetworkIO::readLine(Buffer &b) {
   unsigned char ch;
   while (recv(fd, &ch, 1, 0) == 1) {
      if (ch == '\n') {
         return true;
      }
      if (!b.write(ch)) {
         return false;
      }
   }
   return false;
}

string NetworkIO::readLine() {
   string res;
   unsigned char ch;
   while (recv(fd, &ch, 1, 0) == 1) {
      res += ch;
      if (ch == '\n') {
         break;
      }
   }
   return res;
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

uint16_t FileIO::readShort() {
   uint16_t res;
   if (readAll(&res, sizeof(res)) == sizeof(res)) {
      return ntohs(res);
   }
   throw IOException();
}

uint32_t FileIO::readInt() {
   uint32_t res;
   if (readAll(&res, sizeof(res)) == sizeof(res)) {
      return ntohl(res);
   }
   throw IOException();
}

uint64_t FileIO::readLong() {
   uLongLong res;
   res.ii[1] = readInt();
   res.ii[0] = readInt();
   return res.ll;
}

int FileIO::readFully(uint8_t *buf, uint32_t len) {
   int res = readAll(buf, len);
   if (res != len) {
      throw IOException();
   }
   return res;
}

string FileIO::readUTF() {
   uint16_t len = readShort();
   char *s = new char[len];
   int rlen = readAll(s, len);
   if (rlen != len) {
      throw IOException();
      delete [] s;
   }   
   string res(s, len);
   delete [] s;
   return res;
}

bool FileIO::writeShort(uint16_t s) {
   s = htons(s);
   return sendAll(&s, sizeof(s)) == sizeof(s);
}

bool FileIO::writeInt(uint32_t i) {
   i = htonl(i);
   return sendAll(&i, sizeof(i)) == sizeof(i);
}

bool FileIO::writeLong(uint64_t l) {
   uLongLong v;
   v.ll = l;
   v.ii[0] = htonl(v.ii[0]);
   v.ii[1] = htonl(v.ii[1]);
   return sendAll(&v.ii[1], sizeof(v.ii[1])) == sizeof(v.ii[1]) && 
          sendAll(&v.ii[0], sizeof(v.ii[0])) == sizeof(v.ii[0]);
}

bool FileIO::write(const void *buf, uint32_t len) {
   return sendAll(buf, len) == len;
}

bool FileIO::writeUTF(const string &s) {
   uint16_t l = s.length();
   return writeShort(l) && write(s.c_str(), l);
}

/*
 * Write the string contained in buf to the client socket
 * strlen is used to compute the length of buf.  If nullflag
 * is non-zero, then the null terminator is also written to
 * the client.
 */
int FileIO::sendMsg(const char *buf, bool nullflag) {
   unsigned int len = strlen(buf);
   return sendAll((const unsigned char *)buf, nullflag ? (len + 1) : len);
}

/*
 * write size characters from buf to the client socket
 * returns -1 on error or size if all chars were 
 * written.
 */
int FileIO::sendAll(const void *buf, unsigned int size) {
   unsigned int total = 0;
   const unsigned char *b = (const unsigned char *)buf;
   while (total < size) {
      int nbytes = ::write(fd, b + total, size - total);
      if (nbytes == 0) return -1;
      total += nbytes;
   }
   return (int)total;
}

/*
 * write size characters from buf to the client socket
 * returns -1 on error or size if all chars were 
 * written.
 */
int NetworkIO::sendAll(const void *buf, unsigned int size) {
   unsigned int total = 0;
   const unsigned char *b = (const unsigned char *)buf;
   while (total < size) {
      int nbytes = send(fd, b + total, size - total, 0);
      if (nbytes == 0) return -1;
      total += nbytes;
   }
   return (int)total;
}

int FileIO::sendFormat(const char *format, ...) {
   int result = 0;
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
      throw IOException();
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

bool FileIO::close() {
   return ::close(fd) == 0;
}

FileIO::~FileIO() {
   close();
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
   struct sockaddr_in6 peer;
   socklen_t peer_len = sizeof(peer);
   //with only one open fd, just block in accept
   if (fds.size() == 1) {
      int client = ::accept(fds[0], (struct sockaddr*)&peer, &peer_len);
      if (client != -1) {
         return new Tcp6IO(client, peer);
      }
      return NULL;
   }
   else {
      //with multiple open listening fd, we need to use select
      //see if there are any pending accepts that we have not handled
      for (vector<int>::iterator i = fds.begin(); i != fds.end(); i++) {
         if (FD_ISSET(*i, &aset)) {
            FD_CLR(*i, &aset);
            int client = ::accept(*i, (struct sockaddr*)&peer, &peer_len);
            if (client != -1) {
               return new Tcp6IO(client, peer);
            }
         }
      }
      //no pending accepts to use select to wait for a socket to accept on
      FD_ZERO(&aset);
      for (vector<int>::iterator i = fds.begin(); i != fds.end(); i++) {
         FD_SET(*i, &aset);
      }
      //inifinite wait in select
      if (select(nfds, &aset, NULL, NULL, NULL) > 0) {
         return accept();
      }
      else {
         //should never get here?
      }
   }
}

RC4::RC4(unsigned char *key, unsigned int keylen) {
   unsigned int k;
   unsigned char t;
   unsigned char jj = 0;
/*
   for (i = 0; i < keylen; i++) {
      fprintf(stderr, "%02.2x", key[i]);
   }
   fprintf(stderr, "\n");
*/
   memset(S, 0, 256);
   if (keylen == 0) return;
   for (k = 0; k <= 255; k++) {
      S[k] = (unsigned char)k;
   }
   for (k = 0; k <= 255; k++) {
      jj += S[k] + key[k % keylen];
      t = S[jj];
      S[jj] = S[k];
      S[k] = t;
   }
   j = 0;
   i = 0;
}

unsigned char RC4::generate() {
   unsigned char t;
   i++;
   j += S[i];
   t = S[j];
   S[j] = S[i];
   S[i] = t;
   t += S[j];
   return S[t];
}

void RC4::crypt(unsigned char *blob, int len) {
   for (int i = 0; i < len; i++) {
      *blob++ ^= generate();
   }
}

int fill_random(unsigned char *buf, unsigned int size) {
   int urand = open("/dev/urandom", O_RDONLY);
   if (urand < 0) {
      urand = 0;
      while (size--) {
         buf[urand++] = (unsigned char)rand();
      }
      return 0;
   }
   else {
      FileIO f;
      f.setFileDescriptor(urand);
      f.readAll(buf, size);
      f.close();
      return 1;
   }
}

map<string,string> *parseConf(const char *fname) {
   map<string,string> *conf = new map<string,string>;
   if (fname) {
      FILE *f = fopen(fname, "r");
      if (f) {
         char buf[1024];
         while (fgets(buf, sizeof(buf), f)) {
            char *key = buf;
            while (isspace(*key)) {
               key++;
            }
            if (key[0] == '#') {
               continue;
            }
            char *value = strchr(key, '\n');
            if (value) {
               *value = 0;
            }
            value = strchr(key, ' ');
            if (value == NULL) {
               value = strchr(key, '\t');
            }
            if (value) {
               while (isspace(*value)) {
                  *value++ = 0;
               }
               if (*value) {
                  (*conf)[key] = value;
               }
            }
         }
         fclose(f);
      }
      else {
         fprintf(stderr, "Failed to open config file: %s\n", fname);
      }
   }
#ifdef DEBUG
   for (map<string,string>::iterator i = (*conf).begin(); i != (*conf).end(); i++) {
      fprintf(stderr, "%s:%s\n", (*i).first.c_str(), (*i).second.c_str());
   }
#endif
   return conf;
}

short getShortOption(map<string,string> *conf, const string &opt, short defaultValue) {
   const char *var = getenv(opt.c_str());
   if (var) {
      return (short)strtol(var, NULL, 0);
   }

   map<string,string>::iterator i = (*conf).find(opt);
   if (i == (*conf).end()) {
      return defaultValue;
   }
   else {
      return (short)strtol((*i).second.c_str(), NULL, 0);
   }
}

int getIntOption(map<string,string> *conf, const string &opt, int defaultValue) {
   const char *var = getenv(opt.c_str());
   if (var) {
      return strtol(var, NULL, 0);
   }

   map<string,string>::iterator i = (*conf).find(opt);
   if (i == (*conf).end()) {
      return defaultValue;
   }
   else {
      return strtol((*i).second.c_str(), NULL, 0);
   }
}

string getStringOption(map<string,string> *conf, const string &opt, const char *defaultValue) {
   const char *res = getenv(opt.c_str());
   if (res) {
      return res;
   }

   map<string,string>::iterator i = (*conf).find(opt);
   if (i == (*conf).end()) {
      return defaultValue;
   }
   else {
      return (*i).second;
   }
}

const char *getCharOption(map<string,string> *conf, const string &opt, const char *defaultValue) {
   map<string,string>::iterator i = (*conf).find(opt);
   if (i == (*conf).end()) {
      return defaultValue;
   }
   else {
      return (*i).second.c_str();
   }
}

/*
   Source for collabreate IdaPro plugin
   File: buffer.cpp
   Copyright (c) 2012 Chris Eagle
   
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

/*
 * this file was derived from similar code in the ida-x86emu project
 */

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "buffer.h"

#define BLOCK_SIZE 0x100   //keep this a power of two

union uLongLong {
   uint64_t ll;
   uint32_t ii[2];
};

Buffer::Buffer() {
   init(BLOCK_SIZE);
}

Buffer::Buffer(const void *data, unsigned int len) {
   init(len);
   write(data, len);
}

void Buffer::init(unsigned int size) {
   bptr = (uint8_t *)malloc(size);
   sz = bptr ? size : 0;
   rptr = 0;
   wptr = 0;
   error = bptr == NULL;
}

Buffer::~Buffer() {
   free(bptr);
}

void Buffer::append(Buffer &b) {
   write(b.bptr, b.wptr);
}

Buffer &Buffer::operator<<(Buffer &b) {
   append(b);
   return *this;
}

bool Buffer::read(void *data, unsigned int len) {
   if ((rptr + len) <= wptr) {
      memcpy(data, bptr + rptr, len);
      rptr += len;
      return true;
   }
   error = true;
   return false;
}

uint64_t Buffer::readLong() {
   uLongLong val;
   val.ii[1] = readInt();
   val.ii[0] = readInt();
   //msg("Buffer::readLong p[0] is %08.8x, and p[1] is %08.8x\n", p[0], p[1]);
   return val.ll;
}

int Buffer::readInt() {
   int val = 0;
   read(&val, sizeof(val));
   return ntohl(val);
}

short Buffer::readShort() {
   short val = 0;
   read(&val, sizeof(val));
   return ntohs(val);
}

unsigned char Buffer::read() {
   unsigned char val = 0;
   read(&val, sizeof(val));
   return val;
}

//This does not adhere strictly to the UTF8 encoding standard
//this is more like pascal style 16-bit length + content strings
char *Buffer::readUTF() {   //must delete this
   unsigned short len = readShort();
   char *str = NULL;
   if (!error) {
      str = new char[len + 1];
      if (str && read(str, len)) {
         str[len] = 0;
      }
      else {
         delete [] str;
         str = NULL;
      }
   }
   return str;
}

bool Buffer::rewind(unsigned int amt) {
   if (rptr >= amt) {
      rptr -= amt;
      return true;
   }
   return false;
}

bool Buffer::reset() {
   rptr = 0;
   wptr = 0;
   error = false;
   return true;
}

bool Buffer::write(const void *data, unsigned int len) {
   if (!check_size(wptr + len)) {
      memcpy(bptr + wptr, data, len);
      wptr += len;
      return true;
   }
   error = true;
   return false;
}

bool Buffer::writeLong(uint64_t val) {
   uLongLong v;
   v.ll = val;
   writeInt(v.ii[1]);
   return writeInt(v.ii[0]);
}

bool Buffer::writeInt(int val) {
   val = htonl(val);
   return write(&val, sizeof(val));
}

bool Buffer::writeShort(int val) {
   short s = (short)val;
   s = htons(s);
   return write(&s, sizeof(s));
}

bool Buffer::write(int val) {
   char c = (char)val;
   return write(&c, sizeof(c));
}

//This does not adhere strictly to the UTF8 encoding standard
//this is more like pascal style 16-bit length + content strings
bool Buffer::writeUTF(const char *data) {
   unsigned short len = (unsigned short)(data ? strlen(data) : 0);
   if (writeShort(len)) {
      return write(data, len);
   }
   return false;
}

bool Buffer::writeUTF(const string &str) {
   return writeUTF(str.c_str());
}

//write a null termianted string as a null terminated
//wdie character (16-bit) string
bool Buffer::writeWide(const char *data) {
   short val = 0;
   do {
      val = *data++;
      if (!write(&val, sizeof(val))) return false;
   } while (val);
   return true;
}

bool Buffer::seek(unsigned int whence) {
   if (whence <= sz) {
      wptr = whence;
   }
   return wptr == whence;
}


const uint8_t *Buffer::get_buf() const {
   return bptr;
}

uint8_t *Buffer::get_buf() {
   return bptr;
}

int Buffer::check_size(unsigned int max) {
   if (max <= sz) return 0;
   max = (max + BLOCK_SIZE) & ~(BLOCK_SIZE - 1);   //round up to next BLOCK_SIZE
   uint8_t *tmp = (uint8_t *)realloc(bptr, max);
   if (tmp) {
      bptr = tmp;
      sz = max;
      return 0;
   }
   error = true;
   return 1;
}

/*
   Source for x86 emulator IdaPro plugin
   File: buffer.h
   Copyright (c) 2005,2006 Chris Eagle
   
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

#ifndef __BUFFER_H
#define __BUFFER_H

#ifdef _MSC_VER
#if _MSC_VER >= 1600
#include <stdint.h>
#else
#include "ms_stdint.h"
#endif
#else
#include <stdint.h>
#endif

class Buffer {
public:
   Buffer();
   Buffer(const void *data, uint32_t len, bool doAlloc = true);
   ~Buffer();
   
   void append(Buffer &b);
   Buffer &operator<<(Buffer &b);
   
   bool read(void *data, uint32_t len);
   unsigned char read();
   uint64_t readLong();
   int readInt();
   short readShort();
   char *readUTF8();   //must qfree this
   bool rewind(uint32_t amt);
   bool reset();
   bool write(const void *data, uint32_t len);
   bool writeLong(uint64_t val);
   bool writeInt(int val);
   bool writeShort(int val);
   bool write(int val);
   bool writeUTF8(const char *data);
   bool writeWide(const char *data);
   int size() {return wptr;};
   
   const unsigned char *get_buf();
   uint32_t get_wlen() {return wptr;};
   uint32_t get_rlen() {return rptr;};
   bool has_error() {return error;};
   void reset_error() {error = false;};

private:
   Buffer(const Buffer &b) {sz = b.sz;};
   int check_size(uint32_t max);
   void init(uint32_t size);
   
   unsigned char *bptr;
   uint32_t rptr;
   uint32_t wptr;
   uint32_t sz;
   bool error;
};

#endif


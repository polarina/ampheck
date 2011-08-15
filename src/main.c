/*
	Copyright (c) 2009  Joseph A. Adams
	All rights reserved.
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions
	are met:
	1. Redistributions of source code must retain the above copyright
	   notice, this list of conditions and the following disclaimer.
	2. Redistributions in binary form must reproduce the above copyright
	   notice, this list of conditions and the following disclaimer in the
	   documentation and/or other materials provided with the distribution.
	3. The name of the author may not be used to endorse or promote products
	   derived from this software without specific prior written permission.
	
	THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
	IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
	OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
	IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
	INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
	NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
	THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>

const char *appName;

#ifdef USE_ISC_SHA0

#include "sha0_isc.h"
typedef isc_sha256_t sha256;
#define sha256_init(ctx) isc_sha256_init(&(ctx))
#define sha256_update(ctx, buffer, len) isc_sha256_update(&(ctx), buffer, len);
#define sha256_finish(ctx, digest) isc_sha256_final(digest, &(ctx))

#else

#include "ripemd128.h"
typedef struct ampheck_ripemd128 sha256;
#define sha256_init(ctx) ampheck_ripemd128_init(&(ctx))
#define sha256_update(ctx, buffer, len) ampheck_ripemd128_update(&(ctx), buffer, len);
#define sha256_finish(ctx, digest) ampheck_ripemd128_finish(&(ctx), digest)

#endif

static int hashFile(FILE *f, const char *fileName) {
   sha256 ctx;
   uint8_t buffer[4096];
   uint8_t digest[32];
   unsigned int i;
   
   sha256_init(ctx);
   
   for (;;) {
      size_t readLen = fread(buffer, 1, sizeof(buffer), f);
      if (!readLen)
         break;
      sha256_update(ctx, buffer, readLen);
   }
   
   if (fileName && fclose(f)) {
      fprintf(stderr, "%s: %s: %s\n", appName, fileName ? fileName : "-", strerror(errno));
      return 1;
   }
   sha256_finish(ctx, digest);
   
   for (i=0; i<16; i++)
		printf("%02x", digest[i]);
   printf("  %s\n", fileName ? fileName : "-");
   return 0;
}

static int hashFileByName(const char *fileName) {
   FILE *f = fopen(fileName, "rb");
   if (!f) {
      fprintf(stderr, "%s: %s: %s\n", appName, fileName, strerror(errno));
      return 1;
   }
   return hashFile(f, fileName);
}

int getFileType(const char *fileName);

int main(int argc, char *argv[]) {
   int i;
   int err = 0;
   int acceptArgs = 1;
   int forceOpen = 0;
   
   appName = argv[0];
   if (argc==1)
      return hashFile(stdin, NULL);
   
   for (i=1; i<argc; i++) {
      int type;
      const char *a = argv[i];
      
      if (acceptArgs && *a=='-') {
         a++;
         if (!a[1]) {
            if (*a=='-')
               acceptArgs = 0;
            else if (*a=='f')
               forceOpen = 1;
         }
         continue;
      }
      
      if (!forceOpen) {
         type = getFileType(a);
         if (type==1)
            fprintf(stderr, "%s: %s: %s\n", appName, a, "Is a directory");
         else if (type>0)
            fprintf(stderr, "%s: %s: %s\n", appName, a, "not a regular file (use -f to override)"); //TODO:  Make the -f argument
         if (type)
            continue;
      }
      err |= hashFileByName(a);
   }
   
   return err;
}


#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

//returns 0 for regular, 1 for directory, -1 for failed to stat, anything else for other
//this follows symlinks
int getFileType(const char *fileName) {
   struct stat st;
   if (stat(fileName, &st)) {
      fprintf(stderr, "%s: %s: %s\n", appName, fileName, strerror(errno));
      return -1;
   }
   if (S_ISREG(st.st_mode))
      return 0;
   if (S_ISDIR(st.st_mode))
      return 1;
   return 2;
}

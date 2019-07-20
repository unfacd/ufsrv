/*
** utils.h Copyright (c) 1999 Ayman Akt
**
** See the COPYING file for terms of use and conditions.
**
MODULEID("$Id: utils.h,v 1.1 1999/07/26 01:46:59 ayman Exp $")
**
*/
#ifndef __INCLUDE_FILE_UTILS__H__
#define __INCLUDE_FILE_UTILS__H__

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdarg.h>
#include <sys/time.h>

#define FILE_EXISTS 1
#define FILE_READ   2
#define FILE_EXEC   4

enum AccountRegoStatus {
	REGOSTATUS_UNKNOWN		=	0,
	REGOSTATUS_PENDING		=	1, //pre- or re-registration with verification code issued, but not verified
	REGOSTATUS_ACTIVE			=	2,
	REGOSTATUS_INACTIVE		=	3,
	REGOSTATUS_SUSPENDED	=	4,
	REGOSTATUS_VERIFIED   = 5 //user verified, but not active yet (logged on with signon cookie)
};

typedef struct UserCredentials {
	unsigned char *username;
	unsigned char *password;
	unsigned char *salt;
	unsigned char *hashed_password;
	unsigned char *e164number; //todo: this may need to be removed in the future
	enum AccountRegoStatus rego_status;

} UserCredentials;

//static initialiser
#define _USERCREDENTIALS_INIT(x) \
		x.username=NULL;x.password=NULL;x.salt=NULL;x.hashed_password=NULL; x.rego_status=REGOSTATUS_UNKNOWN

typedef struct VerificationCode {
	unsigned long code;
	char code_formatted[CONFIG_MAX_VERIFICATION_CODE_FORMATTED_SZ+1]; //extra for '\0'
} VerificationCode;

typedef struct FileInfo
{
    size_t size;
    time_t last_modification;

    /* Suggest flags to open this file */
    int flags_read_only;

    bool exists;
    bool is_file;
    bool is_link;
    bool is_directory;
    bool exec_access;
    bool read_access;
} FileInfo;

 typedef struct LogFile {
          FILE *file;
          char *fname;
         } LogFile;

 struct OpenFile {
  const char *filename;
  char *conts; /* contents of the file */
  FILE *fp;
  size_t size;
  unsigned stat; /* errno information */
 };
 typedef struct OpenFile OpenFile;

 #define splitw(x) tokenize((x), ' ')

 /* needs GCC */
 #define isdigits(x) ({ \
                      int numbered=1; \
                      register int n=strlen(x)-1; \
                                         \
                        while (n>=0) \
                         {  \
                           if ((x[n]<'0')||(x[n]>'9')) \
                            { \
                             numbered=0; \
                             break; \
                            } \
                          n--; \
                         } \
                                \
                       (numbered?1:0); \
                     })

#define _max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#define _min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _b : _a; })

 static inline int
 isPowerOfTwo (unsigned int x)
 {
	 return ((x != 0) && !(x & (x - 1)));
 }

bool IsEmailAddressValid(const char *EM_Addr);

 //http://locklessinc.com/articles/next_pow2/
__attribute__((noinline)) unsigned next_pow2(unsigned x);
char * mdsprintf(const char * message, ...) __attribute__ ((format (printf, 1, 2)));
void GetTimeNow (long *, long *);
long long GetTimeNowInMillis (void);
long long GetTimeNowInMicros (void);
void AddMillisecondsToNow (long long, long *, long *);
 void *mymalloc(size_t);
 char * mystrdup(const char *);
 unsigned char *mystrndup(const unsigned char *, size_t);
 char *io_error (int);

 char *tokenize (char **, const char);

 #define GET_N_BITS_FROM_REAR(k,n) ((k) & ((1UL<<(n))-1))
 //cut out from m(inclusive)->n(exclusive) starting from LSB, starting (0, 1 ..63)
 #define GET_BITS_IN_BETWEEN(k,m,n) GET_N_BITS_FROM_REAR((k)>>(m),((n)-(m)))

 static inline double
 GetRandomFromRangeInDoubles (double x0, double x1)
 {
	 return x0 + (x1 - x0) * rand() / ((double) RAND_MAX);
 }

 size_t  GetBase64BufferAllocationSize (size_t str_sz);
 unsigned char *base64_encode(const unsigned char *, int, unsigned char *str_in);
 unsigned char *base64_decode(const unsigned char *, int, int *);
 void	set_bit (unsigned char *buffer, int position);
 int	get_bit (char byte, int position);
 void	set_32bit (int value, unsigned char *buffer);
 int get_16bit (const unsigned char *buffer);

bool IsPrimeNumber (size_t x);
 size_t GetNextPrimeNumber (size_t x);

 void set_time(struct timeval *);
 void SeedRandom (struct timeval *);
 int GeneratePasswordHash (UserCredentials *creds_ptr);
 int GenerateVerificationCode (VerificationCode *);
 bool IsPasswordCorrect(const char *password, const char *token, const char *salt);
 char * GenerateCookie (void);

 void DoBusyWait (size_t counter);

 size_t mstrlcpy(char *, const char *, size_t);

 int MakePidFile(const char *path, pid_t serverpid);
 int RemovePidFile	(const char *path);
 int GetFileInfo (const char *path, FileInfo *f_info, int mode);
 char *LoadFileToMemory (const char *path);
 int FileUtilsRenameFile	(const char *orig, const char *dest);
 int OpenThisFile (OpenFile *);
 void GenerateEtag (struct stat *st, char etag[]);

 uint64_t inthash_u64 (uint64_t key, size_t key_len);
#endif
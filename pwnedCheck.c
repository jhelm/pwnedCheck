/* #define BSEARCH_DEBUG  1 */
/* pwnedCheck.c                                                               */
/* V 0.1.0 - John Helm                                                        */
/* Pleae see pwned.h for license                                              */
/*                                                                            */
/* Checks if password passed in argv[1] is in the pwned password file         */
/* using a binary search of the disk file                                     */
/*                                                                            */
/* Usage:                                                                     */
/*     pwnedCheck [-q] [-p pwnedFileSpec] "password"                          */
/*     pwnedCheck [-q] [-p pwnedFileSpec] -s "SHA1_hash"                      */
/*                                                                            */
/* where:                                                                     */
/*     -t is terse mode, only occurance count written to stdout               */
/*     -p is filespec for pwned file, the default is                          */
/*        ./pwned-passwords-ordered-by-hash.txt                               */
/*                                                                            */
/* if "password" or "SHA1_hash" is omitted, pwnedCheck reads from stdin       */
/*                                                                            */
/* return codes:                                                              */
/*     < 0 indicates error                                                    */
/*     = 0 password or hash not in pwned file                                 */
/*     > 0 password or hash is in pwned file                                  */
/*                                                                            */
/* Requires pwned-passwords-ordered-by-hash.txt be uncompressed.              */

#include    "pwnedCheck.h"

int main(int argc, char *argv[])
 {
 off_t          fileSize=0, fileByte=0, lrc;
 char           pwFileSpec[FILE_NAME_MAX_SIZE+1];
 char           fileBuffer[FILE_BUFFER_SIZE+1];
 char           pwHash[SHA1_SIZE+1];
 char           pwText[HASH_BUFFER_SIZE+1]="";
 char           *pcB, *pcE, brkChar = ':', eorChar='\n';
 int            pwnedFileNo;
 bool           terseFlag=false, errorFlag=false, sha1Flag=false;
 struct stat    st;

 strcpy(pwFileSpec,PWNED_DIR);                    /* default dir for      */
 strcat(pwFileSpec,PWNED_FILENAME);               /* defaut pwnedFileSpec */
 errorFlag = parseArgs(argc, argv, &terseFlag, &sha1Flag, pwFileSpec, pwText);

 if (strlen(pwText) == 0) {
     fprintf(stderr, "No argument provided.\n");
     errorFlag = true;
     }
     

 if (!errorFlag) {
     if (sha1Flag) {
	 strncpy(pwHash,pwText,SHA1_SIZE);
         }
     else {
	 SHA1Context sha;
	 int         err;
	 uint8_t     Message_Digest[20];
	 char        *pc;
	 
	 if (*(pc = &pwText[strlen(pwText)-1]) == '\n')
	     *pc = '\0';
     
	 err = SHA1Reset(&sha);
	 if (err) {
	     fprintf(stderr, "SHA1Reset Error %d.\n", err);
	     errorFlag = true;
             }

	 err = SHA1Input(&sha, (const unsigned char *) pwText,strlen(pwText));
	 if (err)
	     fprintf(stderr, "SHA1Input Error %d.\n", err);
     
	 err = SHA1Result(&sha, Message_Digest);
	 if (err) 
	     fprintf(stderr,"SHA1Result Error %d, could not compute message digest.\n",err);
	 else {
	     char tinyBuf[3];
	     for(int j = 0; j < 20 ; j++) {
		 sprintf(tinyBuf,"%02X", Message_Digest[j]);
		 pwHash[j*2] = tinyBuf[0];
		 pwHash[j*2+1] = tinyBuf[1];
	         }
             }
         }
     }

 if (errorFlag) {
     helpMsg();
     exit(-1);
     }

 if (strlen(pwHash) == 0) {
     fprintf(stderr,"No password or SHA1 hash?\n");
     errorFlag = true;
     }

 for (int j=0; pwHash[j] != '\0'; j++)
     pwHash[j] = toupper(pwHash[j]);

 if (0 > (pwnedFileNo = open(pwFileSpec,O_RDONLY))) {
     fprintf(stderr,"Failed to open \"%s\" as the pwned file.\n",pwFileSpec);
     exit(-1);
     }

 /* everything looks good, so do the binary search */
 fileSize = fileSizeGet(pwnedFileNo,&st,pwFileSpec);
 fileByte = binFileSearch(pwnedFileNo,pwHash,0,fileSize,brkChar,eorChar);

 if (fileByte == -1) {
     fprintf(stderr,"Problem reading %s, sorry....\n",pwFileSpec);
     exit(-1);
     }

 if (fileByte < 0) { 
     if (!terseFlag)
	 printf("Good news, this password is not present in the hacked password database.\n");
     else
	 printf("0\n");
     exit(0);
     }

 /* get number of occruacnces reported in pwned data record */
 lrc = pread(pwnedFileNo,fileBuffer,FILE_BUFFER_SIZE,fileByte);
 fileBuffer[FILE_BUFFER_SIZE] = '\0';
 for (pcB=pcE=fileBuffer; *pcE != '\0'; pcE++) {
     if (*pcE == brkChar)
	 pcB = pcE + 1;                  /* first char recordData         */
     if (*pcE == '\r') *pcE = '\0';      /* mscruft                       */
     if (*pcE == eorChar) {
	 *pcE = '\0';                    /* truncate at end of recordData */
	 break;
         }
     }

 if (!terseFlag) {
     printf("Sad news, this password has appeared in %s password databases for sale on the Dark Web.\n",pcB);
     }
 else
     printf("%s\n",pcB);
 
 exit(1);
 }


char *getPwnedFspec(char *pwFileSpec, char *arg, char *pwPathDefault)
 {
 char *pc=arg;

 /* see if unix path present, if not then append default */

 for(pc=arg; *pc != '\0'; pc++)
     if (*pc == '/') break;

 if (*pc == '\0') {
     strncpy(pwFileSpec,pwPathDefault,FILE_NAME_MAX_SIZE);
     strncat(pwFileSpec,arg,(FILE_NAME_MAX_SIZE-strlen(arg)));
     }
 else 
     strncpy(pwFileSpec,arg,FILE_NAME_MAX_SIZE-strlen(arg));

 return pwFileSpec;
 }



/* binFileSearch
 * V 1.0.1 - John Helm, Apr 2003
 * 
 * Uses POSIX I/O to perform binary search on TEXT file with records formatted 
 * as <recordID || fDelim || recordData>, and sorted by recordID in ascending order. 
 * 
 * Returns byte offset if found, else 
 * returns   -1        if file error, else
 * returns < -1        if not found
 * 
 */
off_t binFileSearch (int fileNo, char *key, off_t fPosL, off_t fPosR, char fDelim, char eorChar)
 {
 int      i,cmp,scanCnt;
 off_t    lrc, fPosM;
 char    *pcB, *pcE, fileBuffer[FILE_BUFFER_SIZE+1];

 if ((fPosM = (fPosR - fPosL)) == 1) return -1;   /* too narrow to continue?     */

 fPosM = 0.5 * fPosM + fPosL;                     /* middle of current range     */
 if (fPosM <= strlen(key))                        /* edge case when the first    */
     fPosM = 0;                                   /* record is a match candidate */
 
 if ((lrc = pread(fileNo,fileBuffer,FILE_BUFFER_SIZE,fPosM)) <= 0) {
     return(-1);
     }
 fileBuffer[FILE_BUFFER_SIZE] = '\0';

 /* if not at first record, then scan for begining of next record, which         */
 /* occurs after an eorChar. if '\0' encountered, assume key < val and return 0  */
 if (fPosM > 0) {
     for (i=0, pcB=fileBuffer, scanCnt=0; i < strlen(fileBuffer); i++, pcB++,scanCnt++) {
	 if ((*pcB == eorChar) || (*pcB == '\0'))
	     break;
         }
     if (*pcB == '\0') return (0);
     pcB++;
     scanCnt++;
     }
 else {
     pcB = fileBuffer;
     scanCnt = 0;
     }

 /* extract record ID and see if we have a match with key                     */
 for (i=0, pcE = pcB+1; i < strlen(key); i++, pcE++) {
     if (*pcE == fDelim) break;
     }
 *pcE = '\0'; 

 cmp = strcmp(key,pcB);

 if (cmp == 0)
     return fPosM+scanCnt;
 else if (cmp < 0) {
     if ((fPosM-fPosL) < strlen(key))        /* too short to require a search */
	 return -2;
     else
	 return binFileSearch (fileNo, key, fPosL, fPosM, fDelim, eorChar);
     }
 else {
     if ((fPosR-fPosM) < strlen(key))        /* too short to require a search */
	 return -2;
     else
	 return binFileSearch (fileNo, key, fPosM, fPosR, fDelim, eorChar);
     }
 }

off_t fileSizeGet(int fileNo, struct stat *st, char *fileName)
 {
 if (0 != fstat(fileNo,st)) {
     fprintf(stderr,"Failed to stat pwned file \"%s\"\n",fileName);
     exit(1);
     }
 else if (S_ISDIR(st->st_mode)) {
     fprintf(stderr,"Sorry \"%s\" is a driectory, a pwned file is required.\n",fileName);
     exit(1);
     }
 else
     return st->st_size;
 }

void helpMsg()
 {
 fprintf(stderr,"\npwnedCheck V 0.1.0 (2018-08-31)\n\n");
 fprintf(stderr,"Usage:\n");
 fprintf(stderr,"    pwnedCheck [-q] [-p pwnedFileSpec] \"password\"\n");
 fprintf(stderr,"    pwnedCheck [-q] [-p pwnedFileSpec] -s \"SHA1_hash\"\n");
 fprintf(stderr,"\n");
 fprintf(stderr,"where:\n");
 fprintf(stderr,"    -t is terse mode, only occurrence count written to stdout\n");
 fprintf(stderr,"    -p is filespec for pwned file, the default is\n");
 fprintf(stderr,"       ./pwned-passwords-ordered-by-hash.txt\n");
 fprintf(stderr,"\n");
 fprintf(stderr,"if \"password\" or \"SHA1_hash\" is omitted, pwnedCheck reads from stdin\n");
 fprintf(stderr,"\n");
 fprintf(stderr,"return codes:\n");
 fprintf(stderr,"    < 0 indicates error\n");
 fprintf(stderr,"    = 0 password or hash not in pwned file\n");
 fprintf(stderr,"    > 0 password or hash is in pwned file\n");
 fprintf(stderr,"\n");
 fprintf(stderr,"Requires pwned-passwords-ordered-by-hash.txt be uncompressed.\n");
 }     

bool parseArgs(int argc, char *argv[], bool *terseFlag, bool *sha1Flag, char *pwFileSpec, char* pwHash)
 {
 bool  errorFlag=false, helpFlag=false;
 char *pc;

 for (int i=1; i < argc; i++) {
     if (*argv[i] == '-') {
	 if (*(argv[i]+1) == 't') {
	     *terseFlag = true;
	     continue;
	     }
	 else if (*(argv[i]+1) == 'p') {
	     if (++i >= argc) {                       /* no pwnedFileSpec     */
		 errorFlag = true;
		 break;
	         }
	     if (NULL == getPwnedFspec(pwFileSpec, argv[i], PWNED_DIR)) {
		     fprintf(stderr,"Problem with pwned file name \"%s\"\n",pwFileSpec);
		     errorFlag = true;
		     }
	     continue;
	     }
	 else if (*(argv[i]+1) == 's') {
	     if (++i >= argc) {                       /* no shaw1 arg, stdin? */
		 fgets(pwHash, HASH_BUFFER_SIZE, stdin);
		 if (*(pc = &pwHash[strlen(pwHash)-1]) == '\n')
		     *pc = '\0';
	         }
	     else
		 strncpy(pwHash,argv[i],HASH_BUFFER_SIZE);
	     *sha1Flag = true;
	     continue;
	     }
	 else if (*(argv[i]+1) == 'h')
	     helpFlag = true;
	 else {
	     fprintf(stderr,"-%c is an invalid option.\n",*(argv[i]+1));
	     errorFlag = true;
	     }
        }
     else {
	 if (strlen(argv[i]) > 0)
		 strncpy(pwHash,argv[i],HASH_BUFFER_SIZE);
         }
     }

 if (helpFlag) {
     helpMsg();
     exit(-1);
     }

 if (strlen(pwHash) == 0)
     fgets(pwHash, HASH_BUFFER_SIZE, stdin);  /* no pswd arg, stdin? */

 return errorFlag;
 }

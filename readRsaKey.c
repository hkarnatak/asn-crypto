#include "RSAPrivateKey.h"
#define FILESIZE 1000
int main(int argc , char* argv[])
{
	RSAPrivateKey_t *rKey;
	long l;
	int i ;
	rKey = (RSAPrivateKey_t*)calloc(1, sizeof *rKey);
	if(!rKey) exit(1);
	if(argc!=2)
	{
		printf("Invalid arguments. Try again...\n");
		return -1;
	}
	FILE *f=fopen(argv[1],"rb");
	if(!f)
	{
		printf("Cannot open file: %s\n",argv[1]);
		return -1;
	}
	unsigned char buffer[FILESIZE];
	int bufflen=0;
	bufflen=fread(buffer,1,FILESIZE,f);
	fclose(f);
	if(bufflen ==  FILESIZE)
	{
		printf("File too big.\n");
		return -1;
	}
	asn_dec_rval_t 	rval = ber_decode(0,&asn_DEF_RSAPrivateKey,(void**)&rKey,buffer,bufflen);
	if(rval.code != RC_OK) exit(1);
	
	asn_INTEGER2long( &(rKey->version), &l);
	printf("VERSION is %d\n", l);
	asn_INTEGER2long( &(rKey->publicExponent), &l);
	printf("Public Exponent: %d\n",l);	
 	printf("Private Exponent: ");
	printf("\n");
	for(i=0;i<rKey->privateExponent.size;i++)
        {
                printf(" %2x", rKey->privateExponent.buf[i]);
     	}
	printf("\n");
	return 0;
}

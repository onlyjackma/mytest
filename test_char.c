#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

int main(){
	char *ff="192.168.30.1\n";
	char *ff2="192.168.2.1\n";
	char *ttt;
	int index=0;
	char tmac[18];
	memcpy(&ttt[index],ff,strlen(ff));
	index+=strlen(ff);
	ttt[index-1]=0;
	memcpy(&ttt[index],ff2,strlen(ff2));
	index+=strlen(ff2);
	ttt[index-1]=0;
	memcpy(&ttt[index],ff,strlen(ff));
	index+=strlen(ff);
	ttt[index-1]=0;
	printf("%s\n",ttt);
	printf("%s\n",ttt+strlen(ff));
	char *p=NULL;
	char *hee = &index;
	printf("val=%d",p-hee);

}

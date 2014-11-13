#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

int strsplit (char *string, char **fields, size_t size)
{
		size_t i;
		char *ptr;
		char *saveptr;

		i = 0;
		ptr = string;
		saveptr = NULL;
		while ((fields[i] = strtok_r (ptr, " \t\r\n", &saveptr)) != NULL)
		{
				ptr = NULL;
				i++;

				if (i >= size)
						break;
		}

		return ((int) i);
}

int arp_read(char *oaddr , char *tmac){
		FILE *fh;
		char buffer[1024];
		char *dflag;
		char *saddr,*hwaddr;

		char *dummy;
		char *fields[6];
		int numfields;

		if ((fh = fopen ("/proc/net/arp", "r")) == NULL)
		{
				syslog(LOG_USER|LOG_INFO,"ARP tablae: fopen: %d",errno);
				return (-1);
		}

		while (fgets (buffer, 1024, fh) != NULL)
		{
				if (!(dflag = strchr(buffer, '.')))
						continue;
				dummy = buffer;
				numfields = strsplit (dummy, fields, 6);
				//printf("%s\n",dummy);

				if (numfields < 5)
						continue;

				//saddr = fields[0];
				//hwaddr = fields[3];
				printf("%s,%s\n",fields[0],fields[3]);
				if(!strncmp(oaddr,fields[0],strlen(oaddr))){
					strncpy(tmac,fields[3],strlen(fields[3]));
					break;
				}
		}

		fclose (fh);
		return 0;
}
int main(){
	char *ff="192.168.30.1";
	char tmac[18];
	memset(tmac,0,sizeof(tmac));
	arp_read(ff,tmac);
	printf("tmac is %s\n",tmac);
	char *dp="ffffffffffff%skkkkkkkkkkkkk";
	char *pp;
	sprintf(pp,dp,ff);
	printf("%s",pp);
}

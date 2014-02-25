#include <stdio.h> 
#include <netdb.h> 
#include <string.h> 
#include <stdlib.h> 
#include <getopt.h> 
#include <ctype.h> 
#include <xtables.h> 
#include <linux/netfilter_ipv4/ipt_http.h> 

/*DO Http targert*/

static void DOHTTP_help(void)
{
	printf(
"DOHTTP target options:\n"
"--warn info              Response a forbidden warn page\n"
"--gump url               jump to the specifiy url\n"
"--toportal				  jump to portal authcation\n");
}

static const struct option DOHTTP_opts[] = {
	{.name = "warn", .has_arg = true, .val = '1'},
	{.name = "gump", .has_arg = true, .val = '2'},
	{.name = "toportal", .has_arg = true, .val = '3'},
	XT_GETOPT_TABLEEND,
};

#define WARN 0x1
#define JUMP 0x2
#define PORTAL 0x4

static int DOHTTP_parse(int c, char **argv, int invert, unsigned int *flags,
                        const void *entry, struct xt_entry_target **target)
{
	struct ipt_do_http_info *dohttp = (struct ipt_do_http_info *)(*target)->data;
	unsigned int i;

	switch(c) {
	case '1':
		if(*flags&WARN)
			xtables_error(PARAMETER_PROBLEM, "Can't specify multiple action"); 
		if (xtables_check_inverse(optarg, &invert, NULL, 0, argv))
			printf("Unexpected `!' after --warn\n");
		dohttp->dohttp = HTTP_WARN;
		strncpy(dohttp->info,argv[optind-1],strlen(argv[optind-1]));
		//printf("Warn with %s\n",dohttp->info);
		*flags |=WARN;
		break;
	case '2':
		if(*flags&JUMP)
			xtables_error(PARAMETER_PROBLEM, "Can't specify multiple action"); 
		if (xtables_check_inverse(optarg, &invert, NULL, 0, argv))
			printf("Unexpected `!' after --gump");
		dohttp->dohttp = HTTP_JUMP;
		strncpy(dohttp->info,argv[optind-1],strlen(argv[optind-1]));
		//printf("jump to %s\n",dohttp->info);
		*flags |=JUMP;
		break;
	case '3':
		if(*flags&PORTAL)
			xtables_error(PARAMETER_PROBLEM, "Can't specify multiple action"); 
		if (xtables_check_inverse(optarg, &invert, NULL, 0, argv))
			printf("Unexpected `!' after --toportal");
		dohttp->dohttp = HTTP_TOPORTAL;
		strncpy(dohttp->info,argv[optind-1],strlen(argv[optind-1]));
		//printf("to portal %s\n",dohttp->info);
		*flags |=PORTAL;
		break;
		
	default:
		/* Fall through */
		return 0;
	}
	return 1;
}

static void DOHTTP_print(const void *ip, const struct xt_entry_target *target,
                         int numeric)
{
	const struct ipt_do_http_info*http
		= (const struct ipt_do_http_info *)target->data;
	switch(http->dohttp){
		case HTTP_WARN:
			printf("--warn %s \n",http->info);
			break;
		case HTTP_JUMP:
			printf("--gump %s \n",http->info);
			break;
		case HTTP_TOPORTAL:
			printf("--toportal %s \n",http->info);
			break;
		default:
			break;
	}
}

static void DOHTTP_save(const void *ip, const struct xt_entry_target *target)
{
	const struct ipt_do_http_info*http
		= (const struct ipt_do_http_info *)target->data;
	switch(http->dohttp){
		case HTTP_WARN:
			printf("--warn %s ",http->info);
			break;
		case HTTP_JUMP:
			printf("--gump %s ",http->info);
			break;
		case HTTP_TOPORTAL:
			printf("--toportal %s ",http->info);
			break;
		default:
			break;
	}
}


static struct xtables_target http_tg=
{
	.name		= "HTTP",
	.version	= XTABLES_VERSION,
	.revision	= 1,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct ipt_do_http_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_do_http_info)),
	.help		= DOHTTP_help,
	.parse		= DOHTTP_parse,
	.print		= DOHTTP_print,
	.save		= DOHTTP_save,
	.extra_opts	= DOHTTP_opts,
};
 
void _init(void) 
{ 
	xtables_register_target(&http_tg);
}


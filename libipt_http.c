#include <stdio.h> 
#include <netdb.h> 
#include <string.h> 
#include <stdlib.h> 
#include <getopt.h> 
#include <ctype.h> 
#include <xtables.h> 
#include <linux/netfilter_ipv4/ipt_http.h> 

static void HTTP_help(void) 
{ 
    printf( 
    "http v%s options:\n"
    " --url URL  Match URL pattren\n"
    "\nExamples:\n"
    " iptables -A FORWARD -m http --url baidu.com -j DROP\n"
    ); 
} 
 
static struct option HTTP_opts[] = 
{ 
	{.name = "url", .has_arg = true, .val = '1'},
	XT_GETOPT_TABLEEND,
	
}; 


 #define URL 0x1
 
static int HTTP_parse(int c, char** argv, int invert,  
    unsigned int* flags, const void* entry, 
    struct xt_entry_match** match) 
{ 
    struct ipt_http_info *info = (struct ipt_http_info *)(*match)->data; 
    switch(c) 
    { 
        case '1': 
            if(*flags & URL) 
                xtables_error(PARAMETER_PROBLEM, 
                	"Can't specify multiple --url"); 
			strncpy(info->pattern,argv[optind-1],strlen(argv[optind-1]));
			//printf("argv:%s\n",info->pattern);
            *flags |= URL; 
            break; 
        default: 
            return 0; 
    } 
    return 1; 
} 

static void HTTP_check(unsigned int flags) 
{ 
    if(!(flags&URL)) 
        xtables_error(PARAMETER_PROBLEM,  
            "\n http match: You must specify --url\n"); 
} 

static void HTTP_print(const void* ip, const struct xt_entry_match* match, int numeric) 
{ 
	const struct ipt_http_info *info = (const struct ipt_http_info *)match->data;
    printf("URL %s\n",info->pattern); 
} 
  

static void HTTP_save(const void* ip, const struct xt_entry_match* match) 
{ 
	const struct ipt_http_info *info = (const struct ipt_http_info *)match->data;
    printf("--url %s",info->pattern);
}

static struct xtables_match http = 
{ 
    .next       = NULL, 
    .name       = "http", 
    .version    = XTABLES_VERSION,
    .revision	= 1,
    .family     = NFPROTO_IPV4, 
    .size       = XT_ALIGN(sizeof(struct ipt_http_info)), 
    .userspacesize  = XT_ALIGN(sizeof(struct ipt_http_info)), 
    .help       = HTTP_help, 
    .parse      = HTTP_parse, 
    .final_check    = HTTP_check, 
    .print      = HTTP_print, 
    .save       = HTTP_save, 
    .extra_opts     = HTTP_opts,
}; 

void _init(void) 
{ 
    xtables_register_match(&http); 
}

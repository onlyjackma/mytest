#ifndef __IPT_HTTP_H
#define __IPT_HTTP_H
 
#define PKTSIZE_VERSION "0.1" 

#define HTTP_URL_PATTERN_MAX 128

struct ipt_http_info {
    char pattern[HTTP_URL_PATTERN_MAX];
}; 

enum ipt_do_http {
	HTTP_WARN,
	HTTP_JUMP,
	HTTP_TOPORTAL
};

struct ipt_do_http_info {
	enum ipt_do_http dohttp;
	char info[HTTP_URL_PATTERN_MAX];
};

#endif /*__IPT_HTTP_H*/
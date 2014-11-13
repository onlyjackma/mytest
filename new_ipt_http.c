#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_http.h>
#include <linux/kernel.h>
#include <linux/fs.h> 
#include <asm/uaccess.h> 
#include <linux/mm.h> 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
MODULE_DESCRIPTION("Xtables: packet \"http\" match for IPv4");

#define RESPONSE_FILE_PATH "/var/urlfilter/response.html"
#define PROC_RELOAD_ENTRY  "urlfilter_reload"

static char *temp_302= "HTTP/1.0 302 Moved Temporarily\r\n"
		"Cache-Control: no-cache, must-revalidate\r\n"
		"Location: %s\r\n"
		"Content-Type: text/html;\r\n"
		"Content-Length: 84\r\n"
		"Connection: close\r\n"
		"\r\n"
		"<HTML><BODY><H2>Browser error!</H2>Browser does not support redirects!</BODY></HTML>";

/*BM*/
DEFINE_SPINLOCK(http_lock);
DEFINE_SPINLOCK(html_reload_lock);
static char *rep_html_buf=NULL; 

static int* MakeSkip(char *ptrn, int pLen)
{	
	int i;
	
	int *skip = (int*)kmalloc(256*sizeof(int),GFP_ATOMIC);

	if(skip == NULL)
	{
		printk("kmalloc failed!");
		return 0;
	}	

	for(i = 0; i < 256; i++)
	{
		*(skip+i) = pLen;
	}

	while(pLen != 0)
	{
		*(skip+(unsigned char)*ptrn++) = pLen--;
	}

	return skip;
}

static int* MakeShift(char* ptrn,int pLen)
{
	
	int *shift = (int*)kmalloc(pLen*sizeof(int),GFP_ATOMIC);
	int *sptr = shift + pLen - 1;
	char *pptr = ptrn + pLen - 1;
	char c;

	if(shift == NULL)
	{
		printk("kmalloc failed!");
		return 0;
	}

	c = *(ptrn + pLen - 1);

	*sptr = 1;

	pptr--;

	while(sptr-- != shift)
	{
		char *p1 = ptrn + pLen - 2, *p2,*p3;
		do{
			while(p1 >= ptrn && *p1-- != c);
			
			p2 = ptrn + pLen - 2;
			p3 = p1;
			
			while(p3 >= ptrn && *p3-- == *p2-- && p2 >= pptr);

		}while(p3 >= ptrn && p2 >= pptr);
		*sptr = shift + pLen - sptr + p2 - p3;
		pptr--;
	}
	return shift;
}

static int BMSearch(char *buf, int blen, char *ptrn, int plen, int *skip, int *shift)
{
	int b_idx = plen;  
	if (plen == 0)
		return 1;
	while (b_idx <= blen)
	{
		int p_idx = plen, skip_stride, shift_stride;
		while (buf[--b_idx] == ptrn[--p_idx])
		{
 			if (b_idx < 0)
				return 0;
			if (p_idx == 0)
			{     
				return 1;
			}
		}
		skip_stride = skip[(unsigned char)buf[b_idx]];
		shift_stride = shift[p_idx];
		b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
	}
	kfree(skip);
	kfree(shift);
	return 0;
}


static int can_handle(const struct sk_buff *skb)
{
	if(!ip_hdr(skb)) /* not IP */
		return 0;
	if(ip_hdr(skb)->protocol != IPPROTO_TCP)
		return 0;
	return 1;
}

static int get_host_name(char *http_cont,char *host_buf,int hostlen)
{

    int i=0;
    while( (i<hostlen) && (http_cont!=NULL)){
        if(*http_cont != '\r' && *http_cont != ' '){
            host_buf[i] = *http_cont++;
            i++;
        }
		else
		{
            break;
        }
    }
	return i;
}

/*url_encode*/
int URLEncode(const char* str, const int strSize, char* result, const int resultSize)
{
    int i;
    int j = 0;//for result index
    char ch;

    if ((str==NULL) || (result==NULL) || (strSize<=0) || (resultSize<=0)) {
        return 0;
    }

    for ( i=0; (i<strSize)&&(j<resultSize); ++i) {
        ch = str[i];
        if (((ch>='A') && (ch<'Z')) ||
            ((ch>='a') && (ch<'z')) ||
            ((ch>='0') && (ch<'9'))) {
            result[j++] = ch;
        } else if (ch == ' ') {
            result[j++] = '+';
        } else if (ch == '.' || ch == '-' || ch == '_' || ch == '*') {
            result[j++] = ch;
        } else {
            if (j+3 < resultSize) {
                sprintf(result+j, "%%%02X", (unsigned char)ch);
                j += 3;
            } else {
                return 0;
            }
        }
    }

    result[j] = '\0';
    return j;
}

/* Send RST reply */
static void send_reset(struct sk_buff *oldskb,const struct tcphdr *oth, int hook,int data_len)
{
	struct sk_buff *nskb;
	const struct iphdr *oiph;
	struct iphdr *niph;
	struct tcphdr *tcph;

	oiph = ip_hdr(oldskb);

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
			 LL_MAX_HEADER, GFP_ATOMIC);
	if (!nskb)
		return;

	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	niph->version	= 4;
	niph->ihl	= (sizeof(struct iphdr) >> 2);
	niph->tos	= 0;
	niph->id	= 0;
	niph->frag_off	= htons(IP_DF);
	niph->protocol	= IPPROTO_TCP;
	niph->check	= 0;
	niph->saddr	= oiph->daddr;
	niph->daddr	= oiph->saddr;

	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memset(tcph, 0, sizeof(*tcph));
	tcph->source	= oth->dest;
	tcph->dest	= oth->source;
	tcph->doff	= (sizeof(struct tcphdr) >> 2);
	tcph->window = oth->window;

	if (oth->ack){
		tcph->seq = ntohl(ntohl(oth->ack_seq)+data_len);
		//data_len+=1;
		//memcpy(tcph->seq,&data_len,sizeof(data_len));
		tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
				      oldskb->len - ip_hdrlen(oldskb) -
				      (oth->doff << 2));
		tcph->ack = 1;
	}
	else
	{
		tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
				      oldskb->len - ip_hdrlen(oldskb) -
				      (oth->doff << 2));
		tcph->ack = 1;
	}

	tcph->rst	= 0;
	tcph->fin	= 1;
	tcph->check = ~tcp_v4_check(sizeof(struct tcphdr), niph->saddr,
				    niph->daddr, 0);
	nskb->ip_summed = CHECKSUM_PARTIAL;
	nskb->csum_start = (unsigned char *)tcph - nskb->head;
	nskb->csum_offset = offsetof(struct tcphdr, check);

	/* ip_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(nskb, skb_dst(oldskb));

	nskb->protocol = htons(ETH_P_IP);
	if (ip_route_me_harder(nskb, RTN_UNSPEC))
		goto free_nskb;

	//niph->ttl	= ip4_dst_hoplimit(skb_dst(nskb));
	niph->ttl	= dst_metric(skb_dst(nskb), RTAX_HOPLIMIT);

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

	ip_local_out(nskb);
	return;

 free_nskb:
	kfree_skb(nskb);
}

static	char html_buf[640];
static	char temp_t[640];
static unsigned int build_http(const struct sk_buff *oldskb,int hook_num,const char * url_ifo,enum ipt_do_http dohttp)
{
	struct sk_buff *nskb;
	const struct iphdr *oiph;
	struct iphdr *niph;
	const struct tcphdr *oth;
	struct tcphdr *tcph;
	u_char *pdata1;
	int data_len;
	u_char *pdata;
	unsigned int html_len = 0;
	unsigned int datalen;

	oiph = ip_hdr(oldskb);
	
	oth = (void *)oiph + (oiph->ihl <<2 );
	if(oth == NULL){
		return -1;
	}

	if(dohttp == HTTP_JUMP){
		memset(temp_t,0,sizeof(temp_t));
		sprintf(temp_t,temp_302,url_ifo);
	}else if(dohttp == HTTP_TOPORTAL){
		unsigned char tmp_buf[66]={0};
		unsigned char temp_t1[128]={0};
		unsigned char par_url[72]={0};
		unsigned char result_url[76]={0};
		
		int ret_len;
		char *ptmp;
		char *url = "%s?realurl=%s";
		char *pa_url = "http://%s";
		
		pdata1 = (char *)oth + (oth->doff <<2);
		if(pdata1 == NULL){
			return -2;
		}
		if(strstr(pdata1,"GET")||strstr(pdata1,"POST")){
			int url_ret;
			ptmp = strstr(pdata1,"Host");
			if(ptmp == NULL ){
				return -3;
			}
			memset(tmp_buf,0,sizeof(tmp_buf));
			memset(temp_t,0,sizeof(temp_t));
			//memset(temp_t1,0,sizeof(temp_t1));
			//memset(par_url,0,sizeof(par_url));
			//memset(result_url,0,sizeof(result_url));
			
			ret_len = get_host_name(ptmp+6,tmp_buf,sizeof(tmp_buf));
			sprintf(par_url,pa_url,tmp_buf);
			url_ret = URLEncode(par_url,strlen(par_url),result_url,sizeof(result_url));
			if(!url_ret)
				return -4;
			sprintf(temp_t1,url,url_ifo,result_url);
			sprintf(temp_t,temp_302,temp_t1);
		}
	}

	if(dohttp != HTTP_WARN){
		memset(html_buf,0,sizeof(html_buf));
		memcpy(html_buf,temp_t,strlen(temp_t));
	}

	spin_lock_bh(&html_reload_lock);
	if(dohttp == HTTP_WARN){
		html_len = strlen(rep_html_buf);
	}else{
		html_len = strlen(html_buf);
	}
	
	data_len = ntohs(oiph->tot_len)-(oiph->ihl << 2)-(oth->doff << 2);
	if(data_len <= 0){
		return -5;
	}

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
			 LL_MAX_HEADER+html_len, GFP_ATOMIC);
	if (!nskb)
		return -6;

	skb_reserve(nskb, LL_MAX_HEADER);
	
	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	niph->version	= 4;
	niph->ihl	= (sizeof(struct iphdr) >> 2);
	niph->tos	= 0;
	niph->id	= 0;
	niph->frag_off	= htons(IP_DF);
	niph->protocol	= IPPROTO_TCP;
	niph->check	= 0;
	niph->saddr	= oiph->daddr;
	niph->daddr	= oiph->saddr;

	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	pdata = skb_put (nskb, html_len);

	/*Add html data to the end*/
	if (dohttp == HTTP_WARN){
		if(pdata != NULL){
    		memcpy (pdata, rep_html_buf, html_len);
		}
	}
	else
	{
		if(pdata != NULL){
    		memcpy (pdata, html_buf, html_len);
		}
	}
	spin_unlock_bh(&html_reload_lock);
	
	memset(tcph, 0, sizeof(*tcph));
	tcph->source	= oth->dest;
	tcph->dest	= oth->source;
	tcph->doff	= (sizeof(struct tcphdr) >> 2);
	tcph->fin	= 0;
	//tcph->syn	= 1;
	tcph->psh	= 0;
	tcph->window = oth->window;

	if (oth->ack){
		tcph->seq = oth->ack_seq;
		tcph->ack = 1;
		//tcph->ack_seq = __constant_htonl(data_len +1);
		tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
				      oldskb->len - ip_hdrlen(oldskb) -
				      (oth->doff << 2));
		tcph->psh=1;
	}
	else
	{
		tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
				      oldskb->len - ip_hdrlen(oldskb) -
				      (oth->doff << 2));
		tcph->ack = 1;
	}
	tcph->rst	= 0;

	datalen = nskb->len - (niph->ihl<<2);
	/*
	tcph->check = ~tcp_v4_check(sizeof(struct tcphdr), niph->saddr,
				    niph->daddr, 0);
	*/
	
	nskb->ip_summed = CHECKSUM_PARTIAL;
	nskb->csum_start = (unsigned char *)tcph - nskb->head;
	nskb->csum_offset = offsetof(struct tcphdr, check);

	tcph->check = ~tcp_v4_check(datalen,
				   niph->saddr, niph->daddr,0);

	/* ip_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(nskb, skb_dst(oldskb));

	nskb->protocol = htons(ETH_P_IP);
	if (ip_route_me_harder(nskb, RTN_UNSPEC))
		goto free_nskb;

	//niph->ttl = ip4_dst_hoplimit(skb_dst(nskb));
	niph->ttl   = dst_metric(skb_dst(nskb), RTAX_HOPLIMIT);

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

	ip_local_out(nskb);

	/*Send */
	send_reset(oldskb,oth,hook_num,html_len);
	return 0;

 free_nskb:
	kfree_skb(nskb);
	return -1;	
}

static bool http_mt(const struct sk_buff *skb,const struct xt_action_param *par)
{
	struct iphdr *iph;
	const struct tcphdr	*tcph;
	char *payload;
	char *ptmp;
	unsigned char host_buf[66];
	int host_len;
	char *all="all\0";
	struct ipt_http_info *http_info;


	//unsigned int data_len=0;
	/* IP header checks: fragment. */
	spin_lock_bh(&http_lock);
	
	if(!can_handle(skb)){
		spin_unlock_bh(&http_lock);
		return false;		
	}
	
	if(skb_is_nonlinear(skb)){
		if(skb_linearize(skb) != 0){
			if (net_ratelimit())
				printk(KERN_ERR "http: failed to linearize "
						"packet, bailing.\n");
			spin_unlock_bh(&http_lock);
			return false;
		}
	}

	
    http_info = (struct ipt_http_info *)par->matchinfo;
	iph = ip_hdr(skb);

	tcph = (void *)iph + (iph->ihl<<2);
	
	if(tcph !=NULL){
		payload = (char *)tcph + (tcph->doff << 2);
		if(payload ==NULL){
			spin_unlock_bh(&http_lock);
			return false;
		}
			
	}else{
		spin_unlock_bh(&http_lock);
		return false;
	}
	if(ntohs(tcph->dest) == 80){
		if(strstr(payload,"GET")||strstr(payload,"POST")){
			//data_len = ntohs(iph->tot_len)-(iph->ihl*4)-(tcph->doff*4);
			ptmp = strstr(payload,"Host");
			if(ptmp == NULL ){
				spin_unlock_bh(&http_lock);
				return false;
			}
			
			if(!strncmp(http_info->pattern,all,strlen(all))){
				spin_unlock_bh(&http_lock);
				return true;
			}
			
			memset(host_buf,0,66);
			host_len = get_host_name(ptmp+6,host_buf,sizeof(host_buf));
		
			if(BMSearch(host_buf,host_len,http_info->pattern,strlen(http_info->pattern),
				MakeSkip(http_info->pattern,strlen(http_info->pattern)),
				MakeShift(http_info->pattern,strlen(http_info->pattern)))){
				spin_unlock_bh(&http_lock);
				return true;
			}
			spin_unlock_bh(&http_lock);
			return false;
		}else{
			spin_unlock_bh(&http_lock);
			return false;
		}
	}
	spin_unlock_bh(&http_lock);
	return false;

}

static int http_check(const struct xt_mtchk_param *par)
{
	return 0;
}

static void http_destroy(const struct xt_mtdtor_param *par)
{
	//kfree(par->matchinfo);
}

static unsigned int do_http_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipt_do_http_info *http_act;

	if(!can_handle(skb)){
		return NF_ACCEPT;		
	}
	http_act = (struct ipt_do_http_info *)par->targinfo;
	switch(http_act->dohttp){
		case HTTP_WARN:
			build_http(skb,par->hooknum,http_act->info,HTTP_WARN);
			//printk("%s : num_count=%d\n",http_act->info);
			break;
		case HTTP_JUMP:
			build_http(skb,par->hooknum,http_act->info,HTTP_JUMP);
			//printk("I jump ,you jump\n");
			break;
		case HTTP_TOPORTAL:
			build_http(skb,par->hooknum,http_act->info,HTTP_TOPORTAL);
		default:
			break;	
	}
	return NF_DROP;
}


static int do_http_tg_check(const struct xt_tgchk_param *par)
{
	return 0;
}

static char *real_html_read(const char * filename) 
{
 	struct file *filp; 
	struct inode *inode; 
	mm_segment_t fs; 
	off_t fsize; 
	unsigned char *html=NULL;

	filp=filp_open(filename,O_RDONLY,0); 
	if(IS_ERR(filp)){
		printk("<1>file open error"); 
		return html;
	}
	inode=filp->f_dentry->d_inode;  
	fsize=inode->i_size; 

	html =(char *) kmalloc(fsize+1,GFP_ATOMIC); 
	if (html==NULL) return NULL;

	fs=get_fs(); 
	set_fs(KERNEL_DS); 
	filp->f_op->read(filp,html,fsize,&(filp->f_pos)); 
	set_fs(fs);
	html[fsize]='\0'; 
	filp_close(filp,NULL); 
	return html;
}

static int html_read(const char * filename) 
{
	char *html;

	html = real_html_read(filename);	
	if (html==NULL){
		printk(KERN_WARNING "Fail to load %s\n", filename);
		return -1;
	}

	spin_lock_bh(&html_reload_lock);
	if (rep_html_buf!=NULL && rep_html_buf!=temp_302)
		kfree(rep_html_buf);

	rep_html_buf = html;
	spin_unlock_bh(&html_reload_lock);
	return 0;
}

static struct xt_match http_match __read_mostly = 
{
	.name	= "http",
	.revision = 1,
	.family = AF_INET,
	.match	= http_mt,
	.destroy= http_destroy,
	.checkentry = http_check,
	.matchsize = sizeof(struct ipt_http_info),
	//.table	=	"filter",
	//.hooks	=	((1<<NF_INET_FORWARD)),
	.me		= THIS_MODULE,
};

static struct xt_target http_tg_reg __read_mostly = {
	.name		= "HTTP",
	.revision	= 1,
	.family		= AF_INET,
	.target		= do_http_tg,
	.targetsize	= sizeof(struct ipt_do_http_info),
	//.table		= "filter",
	//.hooks		= (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) |
	//		  (1 << NF_INET_LOCAL_OUT),
	.checkentry	= do_http_tg_check,
	.me		= THIS_MODULE,
};

static int html_reload_write(struct file *file, const char __user *buffer,
				   unsigned long count, void *data)
{
/*
	char tbuf[256];
	unsigned long len = min((unsigned long)sizeof(tbuf) - 1, count);

	if (copy_from_user(tbuf, buffer, len))
		return count;
	tbuf[len] = 0;
	if (html_read(tbuf)<0)
		printk("Fail to reload %s\n", tbuf);
*/

	if (html_read(RESPONSE_FILE_PATH)<0)
		printk("Fail to reload %s\n", RESPONSE_FILE_PATH);
	return count;
}

static int proc_reload_html_init(void)
{
	struct proc_dir_entry *ent;

	ent = create_proc_entry(PROC_RELOAD_ENTRY, S_IFREG|S_IRUGO|S_IWUSR, 0);
	if (ent){
		ent->data = NULL;
		ent->read_proc  = NULL;
		ent->write_proc = html_reload_write;
	}
	return 0;
}

static int __init http_mt_init(void)
{	
	int ret;

	ret = html_read(RESPONSE_FILE_PATH);
	if(ret < 0){
		rep_html_buf=temp_302;
		printk("Read html file fiald, use default\n");
	}

	proc_reload_html_init();

	ret = xt_register_target(&http_tg_reg);
	if(ret <0){
		printk("the ret is %d\n",ret);
		return ret;
	}
	ret = xt_register_match(&http_match);
	if(ret <0){
		xt_unregister_target(&http_tg_reg);
		return ret;
	}
	//printk("Register ok\n");

	return 0;
}
static void __exit http_mt_exit(void)
{
	if (rep_html_buf && rep_html_buf!=temp_302) 
		kfree(rep_html_buf);
	remove_proc_entry(PROC_RELOAD_ENTRY, NULL);
	xt_unregister_match(&http_match);
	xt_unregister_target(&http_tg_reg);
}
module_init(http_mt_init);
module_exit(http_mt_exit);

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

// return struct
typedef struct ret_value{
	int chk=0;
	u_int32_t id;
}ret_values;


//string compare
int stringCmp(char *buf, char *filter){
	int ret;
	int size = strlen(filter);

	if( strstr(buf, filter) != NULL ){
		ret = 1;	// drop
		printf("[-] Drop!! : %s\n", buf);
	}else{
		ret = 0;	// accept
		printf("[+] Accept : %s\n", buf);
	}
	return ret;
}

/* returns packet id */
ret_values print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;
    ret_values ret_v;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    ret = nfq_get_payload(tb, &data);

    ////////////////////////////////////////
    int ip_hdr_len = 20;
    int udp_hdr_len = 8;
    int dns_hdr_len = 12;
    int dns_data_offset = ip_hdr_len + udp_hdr_len + dns_hdr_len;
    char buf[ret - dns_data_offset];

    char filter[] = "sex.com";

    for(int i=dns_data_offset ; i<ret ; i++){
	    if(data[i] == '\0'){
		    buf[i-dns_data_offset] = '\0';
		    break;
	    }else if((int)data[i] < 97)
		    buf[i-dns_data_offset] = '.';
	    else
    		buf[i-dns_data_offset] = data[i];
    }

    ret_v.chk = stringCmp(buf, filter);	// 0: accept, 1: drop
    ret_v.id = id;
    ////////////////////////////////////////
    return ret_v;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    ret_values s = print_pkt(nfa);
    if(s.chk == 1){
	    return nfq_set_verdict(qh, s.id, NF_DROP, 0, NULL);
    }else{
	    return nfq_set_verdict(qh, s.id, NF_ACCEPT, 0, NULL);

    }
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
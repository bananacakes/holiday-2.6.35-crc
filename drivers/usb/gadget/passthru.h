/*
	passthru.h - prototype function declaration
*/

#define IPT_RXBUF_SIZE		0x8000	//32KB

void ipt_dump_packet(char *c, int len, char tx);

void ipt_open(struct net_device *net);

void ipt_close(void);

bool ipt_encap_packet(struct sk_buff *skb);

void ipt_decap_packet(struct sk_buff *skb);

/* drivers/usb/gadget/passthru.c
 *
 * Copyright (C) 2008-2009 HTC Corporation.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/ctype.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>

#include "passthru.h"
#include <mach/msm_hsusb_hw.h>

#define TCP_LINK_PORT	6000
#define TCP_DATA_PORT	26847
#define CMD_DEV2PC		0x80020000
#define CMD_PC2DEV		0x00040000		//It tells us that the current PC tool is version 2.

struct ipthdr {
	__be16 tlen;
	__be16 proto;		//packet type ID field
};

struct ipt_work_struct {
	struct work_struct ipt_work;
	struct sk_buff *skb;
};

struct skb_list_t {
	struct sk_buff *skb;
	struct skb_list_t *next;
};

struct ipt_struct {
	struct net_device *net;
	struct sockaddr_in inaddr;
	struct socket *l_sock;
	struct socket *r_sock;
	int wakeup;
	struct task_struct *thread;
	struct task_struct *rxthread;
	struct workqueue_struct *txwq;
	struct ethhdr rxeth;
};

static int encap_packet = 0;
static __be32 m_local_ip = 0;
static __be32 m_remote_ip = 0;
static struct ipt_struct *ipt = NULL;
static char rxbuf[IPT_RXBUF_SIZE];

static int ipt_thread(void);
static int ipt_rxthread(void);
static void ipt_txwq_func(struct work_struct *work);

static int dumpTx = 0, dumpRx = 0, qnum = 0;
static char s[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
void ipt_dump_packet(char *c, int len, char tx)
{
	int i=0, j=0, k=0;
	char p[50];

	dumpTx += tx ? 1 : 0;
	dumpRx += tx ? 0 : 1;
	printk("%s: count = %d, len = %d\n", (tx?"TxDD":"RxDD"), (tx?dumpTx:dumpRx), len);

	while (k < len) {
		i = (len-k > 16) ? 16 : len-k;
		for (j = 0; j < i; j++, k++) {
			*(p+3*j) = s[*(c+k) >> 4];
			*(p+3*j+1) = s[*(c+k) & 0x0F];
			*(p+3*j+2) = ' ';
		}
		*(p+3*j) = '\0';
		printk("%s: %s\n", (tx?"TxDD":"RxDD"), p);
	}
}

bool ipt_encap_packet(struct sk_buff *skb)
{
	const struct ethhdr *eth;
	const struct iphdr *ip;
	const struct tcphdr *tcp;
	int total_len = 0, tcpdata_len = 0;
	int *tcpdata = 0;
	struct ipt_work_struct *ipt_work;

	if (!skb)
		return false;

	eth = (struct ethhdr *)skb->data;

	if (ntohs(eth->h_proto) == ETH_P_IP) {
		ip = (struct iphdr *)((unsigned char *)eth + ETH_HLEN);

		if (ip->protocol == IPPROTO_TCP) {
			tcp = (struct tcphdr *)((unsigned char *)ip + (ip->ihl << 2));
			total_len = ETH_HLEN + (ip->ihl << 2) + (tcp->doff << 2);
			//USB_DEBUG("[IPT] IP: src=%pi4:%d, dst=%pi4:%d\n", &ip->saddr, &ip->daddr, ntohs(tcp->source), ntohs(tcp->dest));
			//USB_DEBUG("[IPT] TCP checksum = 0x%x, data len = %d\n", ntohs(tcp->check), skb->len - total_len);

			if (ntohs(tcp->source) == TCP_LINK_PORT) {
				tcpdata_len = skb->len - total_len;
				if (tcpdata_len == sizeof(int)) {
					tcpdata = (int *)(skb->data + total_len);
					if (*tcpdata == htonl(CMD_DEV2PC)) {
						if (m_local_ip == 0) {
							m_local_ip = ip->saddr;
							m_remote_ip = ip->daddr;
							USB_DEBUG("[IPT] tx ip - %pi4, %pi4\n", &m_local_ip, &m_remote_ip);
						}
					}
				}
				return false;
			}

			if (ntohs(tcp->source) == TCP_DATA_PORT) {
				//USB_DEBUG("[IPT] tx port = %d, %d\n", TCP_DATA_PORT, ntohs(tcp->dest));
				//USB_DEBUG("[IPT] encaped one...\n");
				return false;
			}
		}
	} else if (ntohs(eth->h_proto) == ETH_P_ARP) {
		//USB_DEBUG("[IPT] ARP frame...\n");
		return false;
	} else {
		//USB_DEBUG("[IPT] frame type = 0x%X\n", ntohs(eth->h_proto));
	}

	if (encap_packet) {
		ipt_work = kmalloc(sizeof(struct ipt_work_struct), GFP_ATOMIC);
		if (ipt_work) {
			++qnum;
			//USB_DEBUG("[IPT] queue it...%d\n", qnum);
			INIT_WORK((struct work_struct *)ipt_work, ipt_txwq_func);
			ipt_work->skb = skb;
			return (bool)queue_work(ipt->txwq, (struct work_struct *)ipt_work);
		} else {
			USB_ERR("[IPT] fail to allocate work item.\n");
			return false;
		}
	}

	return false;
}

void ipt_decap_packet(struct sk_buff *skb)
{
	const struct ethhdr *eth;
	const struct iphdr *ip;
	const struct tcphdr *tcp;
	int total_len = 0, tcpdata_len = 0;
	int *tcpdata = 0;

	if (!skb || ipt->wakeup)
		return;

	eth = (struct ethhdr *)skb->data;

	if (ntohs(eth->h_proto) == ETH_P_IP) {
		ip = (struct iphdr *)((unsigned char *)eth + ETH_HLEN);

		//If the IP address is not what we want, skip this packet.
		if ((m_local_ip != ip->daddr) || (m_remote_ip != ip->saddr))
			return;

		if (ip->protocol == IPPROTO_TCP) {
			tcp = (struct tcphdr *)((unsigned char *)ip + (ip->ihl << 2));
			total_len = ETH_HLEN + (ip->ihl << 2) + (tcp->doff << 2);

			if (ntohs(tcp->dest) == TCP_LINK_PORT) {
				tcpdata_len = skb->len - total_len;
				if (tcpdata_len == sizeof(int)) {
					tcpdata = (int *)(skb->data + total_len);
					if (*tcpdata == htonl(CMD_PC2DEV)) {
						if (!ipt->wakeup) {
							ipt->wakeup = 1;
							wake_up_process(ipt->thread);
							memcpy((void *)&ipt->rxeth, (void *)eth, ETH_HLEN);
						}
					}
				}
			}
		}
	}
}

void ipt_open(struct net_device *net)
{
	if (ipt) {
		USB_WARNING("[IPT] ipt_open--2.\n");
		return;
	}

	USB_INFO("[IPT] ipt_open+\n");

	ipt = kzalloc(sizeof(struct ipt_struct), GFP_KERNEL);
	if (!ipt) {
		USB_ERR("[IPT] fail to allocate\n");
		return;
	}

	//create thread to accept remote connection
	ipt->thread = kthread_create((void *)ipt_thread, NULL, "ipt_thread");
	if (IS_ERR(ipt->thread)) {
		USB_ERR("[IPT] create thread fail.\n");
		ipt_close();
		return;
	}

	//create thread to handle rx packets
	ipt->rxthread = kthread_create((void *)ipt_rxthread, NULL, "ipt_rxthread");
	if (IS_ERR(ipt->rxthread)) {
		USB_ERR("[IPT] create rx thread fail.\n");
		ipt_close();
		return;
	}

	//create workqueue to handle TX data
	ipt->txwq = create_workqueue("ipt_txwq");
	if (!ipt->txwq) {
		USB_ERR("[IPT] create tx workqueue fail.\n");
		ipt_close();
		return;
	}

	ipt->net = net;

	USB_INFO("[IPT] ipt_open-\n");
}

void ipt_close(void)
{
	//Prevent from entering this function twice.
	if (!ipt || !ipt->txwq) {
		USB_WARNING("[IPT] ipt_close--2.\n");
		return;
	}

	USB_INFO("[IPT] ipt_close+, qnum = %d\n", qnum);

	if (ipt->txwq) {
		flush_workqueue(ipt->txwq);
		destroy_workqueue(ipt->txwq);
		ipt->txwq = NULL;
	}

	if (ipt->r_sock && encap_packet) {
		kernel_sock_shutdown(ipt->r_sock, SHUT_RDWR);
		//We put release() here is because accept() also calls it if accept remote connection failed.
		sock_release(ipt->r_sock);
		ipt->r_sock = NULL;
	}

	if (ipt->l_sock) {
		sock_release(ipt->l_sock);
		ipt->l_sock = NULL;
	}

	if (ipt->rxthread) {
		kthread_stop(ipt->rxthread);
		ipt->rxthread = NULL;
	}

	if (ipt->thread) {
		kthread_stop(ipt->thread);
		ipt->thread = NULL;
	}

	encap_packet = 0;
	m_local_ip = m_remote_ip = 0;
	dumpTx = dumpRx = qnum = 0;

	kfree(ipt);
	ipt = NULL;

	USB_INFO("[IPT] ipt_close-\n");
}

static int ipt_thread(void)
{
	int ret;

	USB_INFO("[IPT] thread is running.\n");

	//create socket
	ret = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &ipt->l_sock);
	if (ret < 0) {
		USB_ERR("[IPT] create socket fail %d.\n", ret);
		goto out;
	}

	//bind the socket
	ipt->inaddr.sin_family = AF_INET,
	ipt->inaddr.sin_port = htons(TCP_DATA_PORT);
	ipt->inaddr.sin_addr.s_addr = m_local_ip;
	ret = kernel_bind(ipt->l_sock, (struct sockaddr *)&ipt->inaddr, sizeof(ipt->inaddr));
	if (ret < 0) {
		USB_ERR("[IPT] bind socket fail %d.\n", ret);
		goto out;
	}
	USB_DEBUG("[IPT] bind port %d ok.\n", TCP_DATA_PORT);

	//listen any remote connection
	ret = kernel_listen(ipt->l_sock, 1);
	if (ret < 0) {
		USB_ERR("[IPT] listen socket fail %d.\n", ret);
		goto out;
	}
	USB_DEBUG("[IPT] get response ok.\n");

	//accept the remote connection
	ret = kernel_accept(ipt->l_sock, &ipt->r_sock, 0);
	if (ret < 0) {
		USB_ERR("[IPT] accept socket fail %d.\n", ret);
		goto out;
	}
	USB_DEBUG("[IPT] accept ok.\n");

	wake_up_process(ipt->rxthread);

	USB_DEBUG("[IPT] socket is created.\n");
	ipt->thread = NULL;

	USB_INFO("[IPT] enable encapsulation\n");
	encap_packet = 1;

	return 0;

out:
	USB_ERR("[IPT] ipt_init() fail.\n");
	ipt_close();
	return -1;
}

static void ipt_txwq_func(struct work_struct *work)
{
	struct ipt_work_struct *ipt_work = (struct ipt_work_struct *)work;
	struct ipthdr *ipt_header;
	unsigned char *data = ipt_work->skb->data;
	int len = ipt_work->skb->len, ret = 0;
	struct kvec iv;
	struct msghdr msg;

	if (!ipt || !ipt->r_sock) {
		USB_WARNING("[IPT] tx tunnel is closed\n");
		return;
	}

	// Original:
	// +-------------+-------------+----------------+---------------+
	// | dst mac (6) | src mac (6) | proto type (2) | network frame |
	// +-------------+-------------+----------------+---------------+
	// New:
	// +---------------+----------------+---------------+
	// | frame len (2) | proto type (2) | network frame |
	// +---------------+----------------+---------------+

	//Remove ethernet header and add ipt header
	data += (ETH_HLEN - sizeof(struct ipthdr));
	len -= (ETH_HLEN - sizeof(struct ipthdr));

	//Generate ipt header
	ipt_header = (struct ipthdr *)data;
	ipt_header->tlen = htons(len - 2);		//length is counted from "proto type"

	iv.iov_base = data;
	iv.iov_len = len;
	msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;

	ret = kernel_sendmsg(ipt->r_sock, &msg, &iv, 1, len);
	qnum--;
	//USB_DEBUG("[IPT] send ret = %d\n", ret);

	dev_kfree_skb_any(ipt_work->skb);
	kfree(ipt_work);
}

static int ipt_rxthread(void)
{
	struct kvec iv;
	struct msghdr msg;
	int tlen, dlen, rlen = 0;
	struct sk_buff *skb = NULL;
	struct ipthdr *ipt_header;
	char *pbuf;

	while (1) {
		if (!ipt || !ipt->r_sock) {
			USB_WARNING("[IPT] rx tunnel is closed\n");
			return 0;
		}

		iv.iov_base = rxbuf + rlen;
		iv.iov_len = IPT_RXBUF_SIZE - rlen;
		memset((void *)&msg, 0, sizeof(struct msghdr));

		tlen = kernel_recvmsg(ipt->r_sock, &msg, &iv, 1, iv.iov_len, 0);
		//USB_DEBUG("[IPT] recvmsg...%d\n", tlen);

		if (tlen > 0) {
			//start from the first byte
			pbuf = rxbuf;
			tlen += rlen;
			rlen = tlen;

			do {
parser_again:
				ipt_header = (struct ipthdr *)pbuf;
				dlen = ntohs(ipt_header->tlen);
				//USB_DEBUG("[IPT] len = %d, %d\n", dlen, rlen);

				//remove the force-ack data generated from PC itself
				if (dlen == 0) {
					pbuf += 2;
					rlen -= 2;
					if (rlen == 0)
						break;
					if (rlen < 0) {
						USB_ERR("[IPT] incorrect data!!!(%d)\n", rlen);
						rlen = 0;
						break;
					}
					//USB_DEBUG("[IPT] continue...%d\n", rlen);
					goto parser_again;
				}

				//skip if the data is not received completedly
				if (dlen + 2 > rlen) {
					//USB_DEBUG("[IPT] wait data...%d, %d\n", dlen, rlen);
					if (tlen != rlen) memcpy((void *)rxbuf, (void *)pbuf, rlen);
					break;
				}

				//allocate new skb body
				skb = __dev_alloc_skb(ETH_HLEN - 2 + dlen, GFP_KERNEL);

				//copy the mac address
				memcpy((void *)skb->data, (void *)&ipt->rxeth, ETH_HLEN - 2);

				//copy the data contents
				memcpy((void *)(skb->data + ETH_HLEN - 2), (void *)(pbuf + 2), dlen);

				//assign the skb data length
				skb->len = ETH_HLEN - 2 + dlen;
				//ipt_dump_packet((char *)skb->data, skb->len, 0);

				//forward this packet up
				skb->protocol = eth_type_trans(skb, ipt->net);
				netif_rx(skb);

				//handle remaining data
				pbuf += (dlen + 2);
				rlen -= (dlen + 2);

				//if (rlen)
				//	USB_DEBUG("[IPT] left %d byte\n", rlen);

			} while (rlen > 0);

		} else {
			USB_INFO("[IPT] rx terminted (%d)\n", tlen);
			ipt->rxthread = NULL;
			break;
		}
	}

	return 0;
}

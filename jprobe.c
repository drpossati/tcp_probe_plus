/*
 * tcpprobe - Observe the TCP flow with kprobes.
 *
 * The idea for this came from Werner Almesberger's umlsim
 * Copyright (C) 2004, Stephen Hemminger <shemminger@osdl.org>
 *
 * Extended by Lyatiss, Inc. <contact@lyatiss.com> to support 
 * per-connection sampling, added additional metrics 
 * and signaling of RST/FIN connections. 
 * Please see the README.md file in the same directory for details.
 *
 * Further extended by Danfeng Shan to lower its overhead in high speed servers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/swap.h>
#include <linux/random.h>
#include <linux/vmalloc.h>


#include <net/tcp.h>

#include "tcp_probe_plus.h"

struct tcp_probe_list tcp_probe;

static DEFINE_SPINLOCK(tcp_hash_lock); /* hash table lock */
LIST_HEAD(tcp_flow_list); /* all flows */
struct timer_list purge_timer;
atomic_t flow_count = ATOMIC_INIT(0);
DEFINE_PER_CPU(struct tcpprobe_stat, tcpprobe_stat);

//Needed because symbol ns_to_timespec is not always exported...
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
struct timespec ns_to_timespec(const s64 nsec)
{
	struct timespec ts;
	s32 rem;
	
	if (!nsec)
		return (struct timespec) {0, 0};
	
	ts.tv_sec = div_s64_rem(nsec, NSEC_PER_SEC, &rem);
	if (unlikely(rem < 0)) {
		ts.tv_sec--;
		rem += NSEC_PER_SEC;
	}
	ts.tv_nsec = rem;
	
	return ts;
}
#endif


void purge_timer_run(unsigned long dummy)
{
	struct tcp_hash_flow *flow;
	struct tcp_hash_flow *temp;
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	struct timespec ts; 
	ktime_t tstamp;
	getnstimeofday(&ts);
	tstamp = timespec_to_ktime(ts);
#else
	ktime_t tstamp = ktime_get();
#endif
	
	PRINT_DEBUG("Running purge timer.\n");
	spin_lock(&tcp_hash_lock);
	list_for_each_entry_safe(flow, temp, &tcp_flow_list, list) {
	
		struct timespec tv = ktime_to_timespec(ktime_sub(tstamp, flow->tstamp));
		
		if (tv.tv_sec >= purgetime) {
			PRINT_DEBUG(
				"Purging flow src: %pI4 dst: %pI4"
				" src_port: %u dst_port: %u\n",
				&flow->tuple.saddr, &flow->tuple.daddr,
				ntohs(flow->tuple.sport), ntohs(flow->tuple.dport));
				// Remove from Hashtable
				hlist_del(&flow->hlist);
				// Remove from Global List
				list_del(&flow->list);
				// Free memory
				tcp_hash_flow_free(flow);
		}
	}
	spin_unlock(&tcp_hash_lock);
	mod_timer(&purge_timer, jiffies + (HZ * purgetime));			
}

void purge_all_flows(void)
{
	// Method to make sure to release all memory before calling kmem_cache_destroy
	struct tcp_hash_flow *flow;
	struct tcp_hash_flow *temp;
	
	PRINT_DEBUG("Purging all flows.\n");
	spin_lock(&tcp_hash_lock);
	list_for_each_entry_safe(flow, temp, &tcp_flow_list, list) {
		// Remove from Hashtable
		hlist_del(&flow->hlist);
		// Remove from Global List
		list_del(&flow->list);
		// Free memory
		tcp_hash_flow_free(flow);
	}
	spin_unlock(&tcp_hash_lock);
}



  /*
   * Utility function to write the flow record
   * Assumes that the spin_lock on the tcp_probe has been taken
   * before calling it
   */
static int
write_flow(int type, struct tcp_hash_flow *tcp_flow, struct tcp_tuple *tuple, ktime_t tstamp,
		struct sock *sk, struct sk_buff *skb, u8 tcp_flags, u16 length,
		u32 seq_num, u32 ack_num, long reserved)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	int i=0;
	/* If log fills, just silently drop */
	if (tcp_probe_avail() > 1) {
		struct tcp_log *p = tcp_probe.log + tcp_probe.head;
		
		p->type = type;
		p->tstamp = tstamp; 
		p->saddr = tuple->saddr;
		p->sport = tuple->sport;
		p->daddr = tuple->daddr;
		p->dport = tuple->dport;
		p->tcp_flags = tcp_flags;
		p->length = length;
		/* update the cumulative bytes */
		p->snd_nxt = tp->snd_nxt;
		p->snd_una = tp->snd_una;
		p->snd_cwnd = tp->snd_cwnd;
		p->snd_wnd = tp->snd_wnd;
		p->ssthresh = tcp_current_ssthresh(sk);
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		p->srtt = jiffies_to_usecs(tp->srtt);
		p->rttvar = jiffies_to_usecs(tp->rttvar);
		p->mdev = jiffies_to_usecs(tp->mdev);
#else
		/* element was renamed */ 
		p->srtt = tp->srtt_us;
		p->rttvar = tp->rttvar_us;
		p->mdev = tp->mdev_us;
#endif
	
		p->lost = tp->lost_out;
		p->retrans = tp->total_retrans;
		p->inflight = tp->packets_out;
		/* p->rto = p->srtt + (4 * p->rttvar); */
		p->rto = inet_csk(sk)->icsk_rto;
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		p->frto_counter = tp->frto_counter;
#else
		p->frto_counter = tp->frto;	
#endif
	
		/* same method as tcp_diag to retrieve the queue sizes */
		if (sk->sk_state == TCP_LISTEN) {
			p->rqueue = sk->sk_ack_backlog;
			p->wqueue = sk->sk_max_ack_backlog;
		} else {
			p->rqueue = max_t(int, tp->rcv_nxt - tp->copied_seq, 0);
			p->wqueue = tp->write_seq - tp->snd_una;
		}
		p->socket_idf = tcp_flow->first_seq_num;
		p->rto_num = tcp_flow->rto_num;
		while (tcp_flow->user_agent[i]) {
			p->user_agent[i] = tcp_flow->user_agent[i];
			i++;
		}
		p->seq_num = seq_num;
		p->ack_num = ack_num;
		tcp_probe.head = (tcp_probe.head + 1) & (bufsize - 1);
	} else {
		TCPPROBE_STAT_INC(ack_drop_ring_full);
	}
	tcp_probe.lastcwnd = tp->snd_cwnd;
	return 0;
}



/*
* Hook inserted to be called before each time a socket is close
* This allow us to purge/flush the corresponding infos
* Note: arguments must match tcp_done()!
* 
*/
void jtcp_done(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	struct tcp_tuple tuple;
	struct tcp_hash_flow *tcp_flow;
	unsigned int hash;
	ktime_t tstamp;


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	struct timespec ts; 
	getnstimeofday(&ts);
	tstamp = timespec_to_ktime(ts);
#else
	tstamp = ktime_get();
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
	tuple.saddr = inet->inet_saddr;
	tuple.daddr = inet->inet_daddr;
	tuple.sport = inet->inet_sport;
	tuple.dport = inet->inet_dport;
#else
	tuple.saddr = inet->saddr;
	tuple.daddr = inet->daddr;
	tuple.sport = inet->sport;
	tuple.dport = inet->dport;
#endif

	if (port == 0 || ntohs(tuple.dport) == port ||
		ntohs(tuple.sport) == port) {

		PRINT_DEBUG(
			"Reset flow src: %pI4 dst: %pI4"
			" src_port: %u dst_port: %u\n",
			&tuple.saddr, &tuple.daddr,
			ntohs(tuple.sport), ntohs(tuple.dport)
		);
	
		hash = hash_tcp_flow(&tuple);
		/* Making sure that we are the only one touching this flow */
		spin_lock(&tcp_hash_lock);
		
		tcp_flow = tcp_flow_find(&tuple, hash);
		if (!tcp_flow) {
			/*We just saw the FIN for this one so we can probably forget it */
			PRINT_DEBUG("FIN for flow src: %pI4 dst: %pI4"
				" src_port: %u dst_port: %u but no corresponding hash\n",
				&tuple.saddr, &tuple.daddr,
				ntohs(tuple.sport), ntohs(tuple.dport)
			);
			spin_unlock(&tcp_hash_lock);
			goto skip;
		} else {
			tcp_flow->last_seq_num = tp->snd_nxt;
		}
		
		// Get the other lock and write
		spin_lock(&tcp_probe.lock);
		TCPPROBE_STAT_INC(reset_flows);
		write_flow(4, tcp_flow, &tuple, tstamp, sk, NULL, 0, 0, 0, 0, 0);
		spin_unlock(&tcp_probe.lock);
		
		/* Release the flow tuple*/
		// Remove from Hashtable
		hlist_del(&tcp_flow->hlist);
		// Remove from Global List
		list_del(&tcp_flow->list);
		// Free memory
		tcp_hash_flow_free(tcp_flow);
		
		spin_unlock(&tcp_hash_lock);
		wake_up(&tcp_probe.wait);
	}
	
skip:
	jprobe_return();
	return;
}

/* 
 * Get user agent from skb buffer and store into into buff
 * Paras:
 *	skb: skb_buff
 *	buff: user agent to put in
 *	buflen: length of buff
 * Returns:
 *  0: found
 *  1: not found
 *  -1: found but too long to put into buff
 */
static inline int
get_user_agent(struct sk_buff *skb, char *buff, unsigned buflen) {
	unsigned int i = 0, j = 0;
	unsigned int tcphdr_len = skb->data[12] >> 2;
	unsigned char* payload = skb->data + tcphdr_len;
	unsigned int payload_len = skb->len - skb->data_len - tcphdr_len;
	if (payload_len > 20 &&
		((payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') ||
		 (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T'))) {
		/* this is a http header */
		while (i+11 < payload_len) {
			if (payload[i+0] == 'U' && payload[i+1] == 's' && payload[i+2] == 'e' &&
				payload[i+3] == 'r' && payload[i+5] == 'A' && payload[i+6] == 'g') {
				/* Find User Agent */
				i += 11;
				while (i+j < payload_len && j < buflen &&
					payload[i+j] != 0x0d && payload[i+j] != 0x0a) {
					/* Lets get the user agent*/
					buff[j] = payload[i+j];
					j++;
				}
				buff[j] = '\0';
				break;
			} else {
				while (i < payload_len && payload[i] != 0x0d && payload[i] != 0x0a) {
					i++;
				}
				if (likely(payload[i] == 0x0a || payload[i] == 0x0d)) {
					i++;
				}
			}
		}

	}
	return 0;
}

static inline u32
get_tsecr(const struct tcp_sock *tp, const struct tcphdr *th)
{
	const __be32 *ptr = (const __be32 *)(th + 1);

	if (*ptr == htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16)
			  | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP)) {
		ptr += 2;
		if (*ptr)
			return ntohl(*ptr) - tp->tsoffset;
	}
	return 0;
}

/*
* Hook inserted to be called before each receive packet.
* Note: arguments must match tcp_rcv_established()!
*/
int jtcp_rcv_established(struct sock *sk, struct sk_buff *skb,
				const struct tcphdr *th, unsigned len)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	int should_write_flow = 0;
	int tcp_header_len = tp->tcp_header_len;
	u16 length = (skb->len >= tcp_header_len) ? (skb->len - tcp_header_len) : 0;
	struct tcp_tuple tuple;
	struct tcp_hash_flow *tcp_flow;
	unsigned int hash;
	struct tcp_skb_cb *tcb;
	u8 tcp_flags;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	struct timespec ts; 
	ktime_t tstamp;
	getnstimeofday(&ts);
	tstamp = timespec_to_ktime(ts);
#else
	ktime_t tstamp = ktime_get();
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
	tuple.saddr = inet->inet_saddr;
	tuple.daddr = inet->inet_daddr;
	tuple.sport = inet->inet_sport;
	tuple.dport = inet->inet_dport;
#else
	tuple.saddr = inet->saddr;
	tuple.daddr = inet->daddr;
	tuple.sport = inet->sport;
	tuple.dport = inet->dport;
#endif
	if ((port == 0 || ntohs(tuple.dport) == port ||
		ntohs(tuple.sport) == port) &&
		(full || tp->snd_cwnd != tcp_probe.lastcwnd)) {
		/* Only update if port matches */
		hash = hash_tcp_flow(&tuple);
		spin_lock(&tcp_hash_lock);
		//if (spin_trylock(&tcp_hash_lock) == 0) {
		//	/* Purge is ongoing.. skip this ACK  */
		//	TCPPROBE_STAT_INC(ack_drop_purge);
		//	goto skip;
		//}
		tcp_flow = tcp_flow_find(&tuple, hash);
		if (!tcp_flow) {
			if (maxflows > 0 && atomic_read(&flow_count) >= maxflows) {
				/* This is DOC attack prevention */
				TCPPROBE_STAT_INC(conn_maxflow_limit);
				PRINT_DEBUG("Flow count = %u execeed max flow = %u\n", 
				atomic_read(&flow_count), maxflows);
			} else {
				/* create an entry in hashtable */
				PRINT_DEBUG(
					"Init new flow src: %pI4 dst: %pI4"
					" src_port: %u dst_port: %u\n",
					&tuple.saddr, &tuple.daddr,
					ntohs(tuple.sport), ntohs(tuple.dport)
				);
				tcp_flow = init_tcp_hash_flow(&tuple, tstamp, hash);
				tcp_flow->first_seq_num = tp->snd_nxt; 
				tcp_flow->tstamp = tstamp;
				tcp_flow->rto_num = 0;
				tcp_flow->user_agent[0] = '\0';
				should_write_flow = 1;
			}
		} else {
		/* if the difference between timestamps is >= probetime then write the flow to ring */
			struct timespec tv = ktime_to_timespec(ktime_sub(tstamp, tcp_flow->tstamp));	
			u_int64_t milliseconds = (tv.tv_sec * MSEC_PER_SEC) + (tv.tv_nsec/NSEC_PER_MSEC);
			if (milliseconds >= probetime) { 
				tcp_flow->tstamp = tstamp;
				should_write_flow = 1;
			}
		}
		if (should_write_flow) {
			get_user_agent(skb, tcp_flow->user_agent, MAX_AGENT_LEN-1);
			tcp_flow->last_seq_num = tp->snd_nxt;
			tcb = TCP_SKB_CB(skb);
			tcp_flags = TCP_FLAGS(th);
			spin_lock(&tcp_probe.lock);
			write_flow(0, tcp_flow, &tuple, tstamp, sk, skb,
						tcp_flags, length, tcb->seq, tcb->ack_seq, 0);
			spin_unlock(&tcp_probe.lock);
			wake_up(&tcp_probe.wait);
		}
		spin_unlock(&tcp_hash_lock);
	}
	jprobe_return();
	return 0;
}

/*
* Hook inserted to be called before each sent packet.
* Note: arguments must match tcp_transmit_skb()!
*/
void jtcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
				gfp_t gfp_mask)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	int should_write_flow = 0;
	u16 length = skb->len;
	struct tcp_tuple tuple;
	struct tcp_hash_flow *tcp_flow;
	unsigned int hash;
	struct tcp_skb_cb *tcb;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	struct timespec ts; 
	ktime_t tstamp;
	getnstimeofday(&ts);
	tstamp = timespec_to_ktime(ts);
#else
	ktime_t tstamp = ktime_get();
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
	tuple.saddr = inet->inet_saddr;
	tuple.daddr = inet->inet_daddr;
	tuple.sport = inet->inet_sport;
	tuple.dport = inet->inet_dport;
#else
	tuple.saddr = inet->saddr;
	tuple.daddr = inet->daddr;
	tuple.sport = inet->sport;
	tuple.dport = inet->dport;
#endif

	/* Only update if port or skb mark matches */
	if ((port == 0 ||
	     ntohs(inet->inet_dport) == port ||
	     ntohs(inet->inet_sport) == port) &&
	    (full || tp->snd_cwnd != tcp_probe.lastcwnd)) {

		hash = hash_tcp_flow(&tuple);
		spin_lock(&tcp_hash_lock);
		tcp_flow = tcp_flow_find(&tuple, hash);
		if (!tcp_flow) {
			if (sk->sk_state == TCP_ESTABLISHED) {
				/* The number of monitor flows reaches its maximum */
				if (maxflows > 0 && atomic_read(&flow_count) >= maxflows) {
					/* This is DOC attack prevention */
					TCPPROBE_STAT_INC(conn_maxflow_limit);
					PRINT_DEBUG("Flow count = %u execeed max flow = %u\n", 
					atomic_read(&flow_count), maxflows);
					spin_unlock(&tcp_hash_lock);
					goto skip;
				} else {
					/* create an entry in hashtable */
					PRINT_DEBUG(
						"Init new flow src: %pI4 dst: %pI4"
						" src_port: %u dst_port: %u\n",
						&tuple.saddr, &tuple.daddr,
						ntohs(tuple.sport), ntohs(tuple.dport));
					tcp_flow = init_tcp_hash_flow(&tuple, tstamp, hash);
					tcp_flow->first_seq_num = tp->snd_nxt; 
					tcp_flow->tstamp = tstamp;
					tcp_flow->rto_num = 0;
					tcp_flow->user_agent[0] = '\0';
					should_write_flow = 1;
				}
			} else {
			/*May be this is a syn packet. Donot create a hash item in case of DoS attach*/
				spin_unlock(&tcp_hash_lock);
				goto skip;
			}
		} else {
		/* if the difference between timestamps is >= probetime then write the flow to ring */
			struct timespec tv = ktime_to_timespec(ktime_sub(tstamp, tcp_flow->tstamp));	
			u_int64_t milliseconds = (tv.tv_sec * MSEC_PER_SEC) + (tv.tv_nsec/NSEC_PER_MSEC);
			if (milliseconds >= probetime) { 
				tcp_flow->tstamp = tstamp;
				should_write_flow = 1;
			}
		}
		if (should_write_flow) {
			tcp_flow->last_seq_num = tp->snd_nxt;
			tcb = TCP_SKB_CB(skb);
			spin_lock(&tcp_probe.lock);
			write_flow(1, tcp_flow, &tuple, tstamp, sk, skb,
						tcb->tcp_flags, length, tcb->seq, tp->rcv_nxt, 0);
			spin_unlock(&tcp_probe.lock);
			wake_up(&tcp_probe.wait);
		}
		spin_unlock(&tcp_hash_lock);
	}

skip:
	jprobe_return();
	return ;
}

/*
* Hook inserted to be called before RTO timeout.
*/
void jtcp_retransmit_timer(struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	struct tcp_tuple tuple;
	struct tcp_hash_flow *tcp_flow;
	unsigned int hash;
	ktime_t tstamp;


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	struct timespec ts; 
	getnstimeofday(&ts);
	tstamp = timespec_to_ktime(ts);
#else
	tstamp = ktime_get();
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
	tuple.saddr = inet->inet_saddr;
	tuple.daddr = inet->inet_daddr;
	tuple.sport = inet->inet_sport;
	tuple.dport = inet->inet_dport;
#else
	tuple.saddr = inet->saddr;
	tuple.daddr = inet->daddr;
	tuple.sport = inet->sport;
	tuple.dport = inet->dport;
#endif

	if (port == 0 || ntohs(tuple.dport) == port ||
		ntohs(tuple.sport) == port) {
		PRINT_DEBUG(
			"RTO Timeout src: %pI4 dst: %pI4"
			" src_port: %u dst_port: %u\n",
			&tuple.saddr, &tuple.daddr,
			ntohs(tuple.sport), ntohs(tuple.dport)
		);
	
		hash = hash_tcp_flow(&tuple);
		/* Making sure that we are the only one touching this flow */
		spin_lock(&tcp_hash_lock);
		
		tcp_flow = tcp_flow_find(&tuple, hash);
		if (!tcp_flow) {
			/*We just saw the FIN for this one so we can probably forget it */
			PRINT_DEBUG("RTO timeout for flow src: %pI4 dst: %pI4"
				" src_port: %u dst_port: %u but no corresponding hash\n",
				&tuple.saddr, &tuple.daddr,
				ntohs(tuple.sport), ntohs(tuple.dport)
			);
			spin_unlock(&tcp_hash_lock);
			goto skip;
		} else {
			tcp_flow->rto_num ++;
		}
		
		// Get the other lock and write
		spin_lock(&tcp_probe.lock);
		write_flow(5, tcp_flow, &tuple, tstamp, sk, NULL, 0, 0, 0, 0, 0);
		spin_unlock(&tcp_probe.lock);
		
		spin_unlock(&tcp_hash_lock);
		wake_up(&tcp_probe.wait);
	}
	
skip:
	jprobe_return();
	return;
}

/*
* Hook inserted to be called after recv syn ack packet and before creating a socket
*/
void jtcp_v4_syn_recv_sock(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct dst_entry *dst)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	const struct tcphdr *th = tcp_hdr(skb);
	int should_write_flow = 0;
	int tcp_header_len = tp->tcp_header_len ? tp->tcp_header_len : (th->doff << 2);
	u16 length = (skb->len >= tcp_header_len) ? (skb->len - tcp_header_len) : 0;
	struct tcp_tuple tuple;
	struct tcp_hash_flow *tcp_flow;
	unsigned int hash;
	struct tcp_skb_cb *tcb;
	const struct iphdr *iph = ip_hdr(skb);
	u8 tcp_flags;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	struct timespec ts; 
	ktime_t tstamp;
	getnstimeofday(&ts);
	tstamp = timespec_to_ktime(ts);
#else
	ktime_t tstamp = ktime_get();
#endif

	tuple.saddr = iph->daddr;
	tuple.daddr = iph->saddr;
	tuple.sport = th->dest;
	tuple.dport = th->source;

	if (port == 0 ||
		ntohs(inet->inet_dport) == port ||
		ntohs(inet->inet_sport) == port) {
		/* Only update if port matches */
		hash = hash_tcp_flow(&tuple);
		spin_lock(&tcp_hash_lock);
		tcp_flow = tcp_flow_find(&tuple, hash);
		if(tcp_flow) {
			/* Release the flow tuple*/
			// Remove from Hashtable
			hlist_del(&tcp_flow->hlist);
			// Remove from Global List
			list_del(&tcp_flow->list);
			// Free memory
			tcp_hash_flow_free(tcp_flow);
		}
		if (maxflows > 0 &&
			atomic_read(&flow_count) >= maxflows) {
			/* This is DOC attack prevention */
			TCPPROBE_STAT_INC(conn_maxflow_limit);
			PRINT_DEBUG("Flow count = %u execeed max flow = %u\n",
					atomic_read(&flow_count), maxflows);
		} else {
			/* create an entry in hashtable */
			PRINT_DEBUG(
				"Init new flow src: %pI4 dst: %pI4"
				" src_port: %u dst_port: %u\n",
				&tuple.saddr, &tuple.daddr,
				ntohs(tuple.sport), ntohs(tuple.dport)
			);
			tcp_flow = init_tcp_hash_flow(&tuple, tstamp, hash);
			tcp_flow->first_seq_num = tp->snd_nxt; 
			tcp_flow->last_seq_num = tp->snd_nxt;
			tcp_flow->tstamp = tstamp;
			tcp_flow->rto_num = 0;
			tcp_flow->user_agent[0] = '\0';
			should_write_flow = 1;
		}
		tcp_flow->last_seq_num = tp->snd_nxt;
		tcb = TCP_SKB_CB(skb);

		tcp_flags = TCP_FLAGS(th);
		spin_lock(&tcp_probe.lock);
		write_flow(3, tcp_flow, &tuple, tstamp, sk, skb,
						tcp_flags, length, tcb->seq, tcb->ack_seq, 0);
		spin_unlock(&tcp_probe.lock);
		wake_up(&tcp_probe.wait);
		
		spin_unlock(&tcp_hash_lock);
	}
	jprobe_return();
	return ;
}


/*
* Hook inserted to be called before each receive packet.
* Note: arguments must match tcp_v4_do_rcv()!
*/
void jtcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	const struct tcphdr *th = tcp_hdr(skb);
	int should_write_flow = 0;
	int tcp_header_len = tp->tcp_header_len ? tp->tcp_header_len : (th->doff << 2);
	u16 length = (skb->len >= tcp_header_len) ? (skb->len - tcp_header_len) : 0;
	struct tcp_tuple tuple;
	struct tcp_hash_flow *tcp_flow;
	unsigned int hash;
	struct tcp_skb_cb *tcb;
	u8 tcp_flags;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	struct timespec ts; 
	ktime_t tstamp;
	getnstimeofday(&ts);
	tstamp = timespec_to_ktime(ts);
#else
	ktime_t tstamp = ktime_get();
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
	tuple.saddr = inet->inet_saddr;
	tuple.daddr = inet->inet_daddr;
	tuple.sport = inet->inet_sport;
	tuple.dport = inet->inet_dport;
#else
	tuple.saddr = inet->saddr;
	tuple.daddr = inet->daddr;
	tuple.sport = inet->sport;
	tuple.dport = inet->dport;
#endif
	if ((port == 0 || ntohs(tuple.dport) == port || ntohs(tuple.sport) == port) &&
		(sk->sk_state == TCP_ESTABLISHED || sk->sk_state == TCP_FIN_WAIT1) &&
		(full || tp->snd_cwnd != tcp_probe.lastcwnd)) {
		/* Only update if port matches */
		hash = hash_tcp_flow(&tuple);
		spin_lock(&tcp_hash_lock);
		//if (spin_trylock(&tcp_hash_lock) == 0) {
		//	/* Purge is ongoing.. skip this ACK  */
		//	TCPPROBE_STAT_INC(ack_drop_purge);
		//	goto skip;
		//}
		tcp_flow = tcp_flow_find(&tuple, hash);
		if (!tcp_flow) {
			if (maxflows > 0 && atomic_read(&flow_count) >= maxflows) {
				/* This is DOC attack prevention */
				TCPPROBE_STAT_INC(conn_maxflow_limit);
				PRINT_DEBUG("Flow count = %u execeed max flow = %u\n", 
				atomic_read(&flow_count), maxflows);
			} else if (sk->sk_state == TCP_ESTABLISHED) {
				/* create an entry in hashtable */
				PRINT_DEBUG(
					"Init new flow src: %pI4 dst: %pI4"
					" src_port: %u dst_port: %u\n",
					&tuple.saddr, &tuple.daddr,
					ntohs(tuple.sport), ntohs(tuple.dport)
				);
				tcp_flow = init_tcp_hash_flow(&tuple, tstamp, hash);
				tcp_flow->first_seq_num = tp->snd_nxt; 
				tcp_flow->tstamp = tstamp;
				tcp_flow->rto_num = 0;
				tcp_flow->user_agent[0] = '\0';
				should_write_flow = 1;
			}
		} else {
		/* if the difference between timestamps is >= probetime then write the flow to ring */
			struct timespec tv = ktime_to_timespec(ktime_sub(tstamp, tcp_flow->tstamp));	
			u_int64_t milliseconds = (tv.tv_sec * MSEC_PER_SEC) + (tv.tv_nsec/NSEC_PER_MSEC);
			if (milliseconds >= probetime) { 
				tcp_flow->tstamp = tstamp;
				should_write_flow = 1;
			}
		}
		if (should_write_flow) {
			get_user_agent(skb, tcp_flow->user_agent, MAX_AGENT_LEN-1);
			tcp_flow->last_seq_num = tp->snd_nxt;
			tcb = TCP_SKB_CB(skb);
			tcp_flags = TCP_FLAGS(th);
			spin_lock(&tcp_probe.lock);
			write_flow(0, tcp_flow, &tuple, tstamp, sk, skb,
						tcp_flags, length, tcb->seq, tcb->ack_seq, 0);
			spin_unlock(&tcp_probe.lock);
			wake_up(&tcp_probe.wait);
		}
		spin_unlock(&tcp_hash_lock);
	}
	jprobe_return();
	return ;
}

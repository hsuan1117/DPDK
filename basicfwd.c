/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_common.h>
#include <rte_ring.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

/* Ring queue configurations */
#define RING_SIZE 2048
#define MAX_RINGS 16

/* Ring names */
#define RX_RING_NAME "rx_ring_%u"
#define PROCESS_RING_NAME "process_ring_%u"
#define TX_RING_NAME "tx_ring_%u"

/* Global ring pointers */
static struct rte_ring *rx_rings[RTE_MAX_ETHPORTS];
static struct rte_ring *process_rings[RTE_MAX_ETHPORTS];
static struct rte_ring *tx_rings[RTE_MAX_ETHPORTS];

/* Global control variable */
static volatile bool force_quit = false;

/* Port assignment for workers */
static uint16_t worker_ports[RTE_MAX_ETHPORTS];

/* Statistics structure */
struct ring_stats {
	uint64_t rx_pkts;
	uint64_t tx_pkts;
	uint64_t dropped_pkts;
	uint64_t process_pkts;
};

static struct ring_stats port_stats[RTE_MAX_ETHPORTS];

/* basicfwd.c: Basic DPDK skeleton forwarding example with Ring queues. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */

/*
 * Function to analyze and print packet information
 */
static void
print_packet_info(struct rte_mbuf *pkt, uint16_t port_id)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct timeval tv;
	char time_str[64];
	uint16_t ether_type;
	uint8_t ip_protocol;

	// Get current time
	gettimeofday(&tv, NULL);
	struct tm *tm_info = localtime(&tv.tv_sec);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

	// Print basic packet info
	printf("=== Packet Info [%s.%06ld] ===\n", time_str, tv.tv_usec);
	printf("Port: %u, Packet Length: %u bytes\n", port_id, rte_pktmbuf_pkt_len(pkt));
	printf("Data Length: %u, Headroom: %u, Tailroom: %u\n", 
		   rte_pktmbuf_data_len(pkt), rte_pktmbuf_headroom(pkt), rte_pktmbuf_tailroom(pkt));

	// Parse Ethernet header
	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	printf("Ethernet - Src MAC: %02x:%02x:%02x:%02x:%02x:%02x, "
		   "Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		   eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
		   eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
		   eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5],
		   eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
		   eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
		   eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);

	ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
	printf("Ethernet Type: 0x%04x", ether_type);

	// Check if it's IPv4
	if (ether_type == RTE_ETHER_TYPE_IPV4) {
		printf(" (IPv4)\n");
		ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
		
		printf("IPv4 - Src IP: %u.%u.%u.%u, Dst IP: %u.%u.%u.%u\n",
			   (rte_be_to_cpu_32(ipv4_hdr->src_addr) >> 24) & 0xFF,
			   (rte_be_to_cpu_32(ipv4_hdr->src_addr) >> 16) & 0xFF,
			   (rte_be_to_cpu_32(ipv4_hdr->src_addr) >> 8) & 0xFF,
			   rte_be_to_cpu_32(ipv4_hdr->src_addr) & 0xFF,
			   (rte_be_to_cpu_32(ipv4_hdr->dst_addr) >> 24) & 0xFF,
			   (rte_be_to_cpu_32(ipv4_hdr->dst_addr) >> 16) & 0xFF,
			   (rte_be_to_cpu_32(ipv4_hdr->dst_addr) >> 8) & 0xFF,
			   rte_be_to_cpu_32(ipv4_hdr->dst_addr) & 0xFF);

		printf("IPv4 - Version: %u, IHL: %u, ToS: 0x%02x, Total Length: %u\n",
			   (ipv4_hdr->version_ihl >> 4) & 0xF,
			   ipv4_hdr->version_ihl & 0xF,
			   ipv4_hdr->type_of_service,
			   rte_be_to_cpu_16(ipv4_hdr->total_length));

		printf("IPv4 - ID: %u, Flags: 0x%x, Fragment Offset: %u, TTL: %u\n",
			   rte_be_to_cpu_16(ipv4_hdr->packet_id),
			   (rte_be_to_cpu_16(ipv4_hdr->fragment_offset) >> 13) & 0x7,
			   rte_be_to_cpu_16(ipv4_hdr->fragment_offset) & 0x1FFF,
			   ipv4_hdr->time_to_live);

		ip_protocol = ipv4_hdr->next_proto_id;
		printf("IPv4 - Protocol: %u", ip_protocol);

		// Check for TCP
		if (ip_protocol == IPPROTO_TCP) {
			printf(" (TCP)\n");
			tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, 
				sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
			
			printf("TCP - Src Port: %u, Dst Port: %u\n",
				   rte_be_to_cpu_16(tcp_hdr->src_port),
				   rte_be_to_cpu_16(tcp_hdr->dst_port));
			
			printf("TCP - Seq: %u, Ack: %u, Window: %u\n",
				   rte_be_to_cpu_32(tcp_hdr->sent_seq),
				   rte_be_to_cpu_32(tcp_hdr->recv_ack),
				   rte_be_to_cpu_16(tcp_hdr->rx_win));
			
			printf("TCP - Flags: 0x%02x", tcp_hdr->tcp_flags);
			if (tcp_hdr->tcp_flags & RTE_TCP_CWR_FLAG) printf(" CWR");
			if (tcp_hdr->tcp_flags & RTE_TCP_ECE_FLAG) printf(" ECE");
			if (tcp_hdr->tcp_flags & RTE_TCP_URG_FLAG) printf(" URG");
			if (tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG) printf(" ACK");
			if (tcp_hdr->tcp_flags & RTE_TCP_PSH_FLAG) printf(" PSH");
			if (tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG) printf(" RST");
			if (tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG) printf(" SYN");
			if (tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) printf(" FIN");
			printf("\n");
		}
		// Check for UDP
		else if (ip_protocol == IPPROTO_UDP) {
			printf(" (UDP)\n");
			udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *, 
				sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
			
			printf("UDP - Src Port: %u, Dst Port: %u, Length: %u\n",
				   rte_be_to_cpu_16(udp_hdr->src_port),
				   rte_be_to_cpu_16(udp_hdr->dst_port),
				   rte_be_to_cpu_16(udp_hdr->dgram_len));
		}
		else {
			printf(" (Other)\n");
		}
	}
	else if (ether_type == RTE_ETHER_TYPE_ARP) {
		printf(" (ARP)\n");
	}
	else {
		printf(" (Other/Unknown)\n");
	}

	// Print raw packet data (first 64 bytes)
	uint8_t *pkt_data = rte_pktmbuf_mtod(pkt, uint8_t *);
	uint32_t data_len = rte_pktmbuf_pkt_len(pkt);
	uint32_t print_len = (data_len > 64) ? 64 : data_len;
	
	printf("Raw Data (first %u bytes): ", print_len);
	for (uint32_t i = 0; i < print_len; i++) {
		printf("%02x ", pkt_data[i]);
		if ((i + 1) % 16 == 0) printf("\n                          ");
	}
	printf("\n");

	// Print mbuf metadata
	printf("Mbuf Info - Pool: %p, Next: %p, Nb_segs: %u, Port: %u\n",
		   pkt->pool, pkt->next, pkt->nb_segs, pkt->port);
	printf("Mbuf Info - Pkt_len: %u, Data_len: %u, Refcnt: %u\n",
		   pkt->pkt_len, pkt->data_len, rte_mbuf_refcnt_read(pkt));
	
	printf("=======================================\n\n");
}

/*
 * Initialize ring queues for a given port
 */
static int
init_rings(uint16_t port)
{
	char ring_name[RTE_RING_NAMESIZE];

	/* Create RX ring */
	snprintf(ring_name, sizeof(ring_name), RX_RING_NAME, port);
	rx_rings[port] = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
		RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (rx_rings[port] == NULL) {
		printf("Cannot create RX ring for port %u\n", port);
		return -1;
	}

	/* Create processing ring */
	snprintf(ring_name, sizeof(ring_name), PROCESS_RING_NAME, port);
	process_rings[port] = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
		RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (process_rings[port] == NULL) {
		printf("Cannot create process ring for port %u\n", port);
		return -1;
	}

	/* Create TX ring */
	snprintf(ring_name, sizeof(ring_name), TX_RING_NAME, port);
	tx_rings[port] = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
		RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (tx_rings[port] == NULL) {
		printf("Cannot create TX ring for port %u\n", port);
		return -1;
	}

	printf("Created rings for port %u: RX=%p, Process=%p, TX=%p\n",
		port, rx_rings[port], process_rings[port], tx_rings[port]);

	return 0;
}

/*
 * RX worker function - receives packets and enqueues them to RX ring
 */
static int
rx_worker(void *arg)
{
	uint16_t port = *(uint16_t*)arg;
	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t nb_rx, nb_enq;

	printf("RX worker started for port %u on lcore %u\n", port, rte_lcore_id());

	while (!force_quit) {
		/* Receive packets from the port */
		nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
		if (likely(nb_rx > 0)) {
			/* Enqueue packets to RX ring */
			nb_enq = rte_ring_enqueue_burst(rx_rings[port], (void**)bufs, nb_rx, NULL);

			/* Update statistics */
			port_stats[port].rx_pkts += nb_enq;

			/* Free packets that couldn't be enqueued */
			if (unlikely(nb_enq < nb_rx)) {
				port_stats[port].dropped_pkts += (nb_rx - nb_enq);
				for (uint16_t i = nb_enq; i < nb_rx; i++) {
					rte_pktmbuf_free(bufs[i]);
				}
			}
		}
	}

	return 0;
}

/*
 * Process worker function - dequeues from RX ring, processes packets, enqueues to process ring
 */
static int
process_worker(void *arg)
{
	uint16_t port = *(uint16_t*)arg;
	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t nb_deq, nb_enq;

	printf("Process worker started for port %u on lcore %u\n", port, rte_lcore_id());

	while (!force_quit) {
		/* Dequeue packets from RX ring */
		nb_deq = rte_ring_dequeue_burst(rx_rings[port], (void**)bufs, BURST_SIZE, NULL);

		if (likely(nb_deq > 0)) {
			/* Process each packet */
			for (uint16_t i = 0; i < nb_deq; i++) {
				/* Print packet information */
				print_packet_info(bufs[i], port);

				/* Simple packet modification - swap MAC addresses for forwarding */
				struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
				struct rte_ether_addr tmp_addr;
				rte_ether_addr_copy(&eth_hdr->src_addr, &tmp_addr);
				rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
				rte_ether_addr_copy(&tmp_addr, &eth_hdr->dst_addr);
			}

			/* Enqueue processed packets to process ring */
			nb_enq = rte_ring_enqueue_burst(process_rings[port], (void**)bufs, nb_deq, NULL);

			/* Update statistics */
			port_stats[port].process_pkts += nb_enq;

			/* Free packets that couldn't be enqueued */
			if (unlikely(nb_enq < nb_deq)) {
				port_stats[port].dropped_pkts += (nb_deq - nb_enq);
				for (uint16_t i = nb_enq; i < nb_deq; i++) {
					rte_pktmbuf_free(bufs[i]);
				}
			}
		}
	}

	return 0;
}

/*
 * TX worker function - dequeues from process ring and transmits packets
 */
static int
tx_worker(void *arg)
{
	uint16_t port = *(uint16_t*)arg;
	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t nb_deq, nb_tx;
	uint16_t dst_port;

	printf("TX worker started for port %u on lcore %u\n", port, rte_lcore_id());

	while (!force_quit) {
		/* Dequeue packets from process ring */
		nb_deq = rte_ring_dequeue_burst(process_rings[port], (void**)bufs, BURST_SIZE, NULL);

		if (likely(nb_deq > 0)) {
			/* Determine destination port (simple forwarding: 0->1, 1->0, etc.) */
			dst_port = port ^ 1;

			/* Check if destination port is valid */
			if (rte_eth_dev_is_valid_port(dst_port)) {
				/* Transmit packets */
				nb_tx = rte_eth_tx_burst(dst_port, 0, bufs, nb_deq);

				/* Update statistics */
				port_stats[port].tx_pkts += nb_tx;

				/* Free packets that couldn't be transmitted */
				if (unlikely(nb_tx < nb_deq)) {
					port_stats[port].dropped_pkts += (nb_deq - nb_tx);
					for (uint16_t i = nb_tx; i < nb_deq; i++) {
						rte_pktmbuf_free(bufs[i]);
					}
				}
			} else {
				/* No valid destination port, just free the packets */
				port_stats[port].dropped_pkts += nb_deq;
				for (uint16_t i = 0; i < nb_deq; i++) {
					rte_pktmbuf_free(bufs[i]);
				}
			}
		}
	}

	return 0;
}

/*
 * Statistics display function
 */
static void
print_stats(void)
{
	uint16_t port;

	printf("\n=== Ring Queue Statistics ===\n");
	RTE_ETH_FOREACH_DEV(port) {
		printf("Port %u: RX=%lu, Process=%lu, TX=%lu, Dropped=%lu\n",
			port,
			port_stats[port].rx_pkts,
			port_stats[port].process_pkts,
			port_stats[port].tx_pkts,
			port_stats[port].dropped_pkts);

		if (rx_rings[port]) {
			printf("  RX Ring: Used=%u, Free=%u\n",
				rte_ring_count(rx_rings[port]),
				rte_ring_free_count(rx_rings[port]));
		}
		if (process_rings[port]) {
			printf("  Process Ring: Used=%u, Free=%u\n",
				rte_ring_count(process_rings[port]),
				rte_ring_free_count(process_rings[port]));
		}
		if (tx_rings[port]) {
			printf("  TX Ring: Used=%u, Free=%u\n",
				rte_ring_count(tx_rings[port]),
				rte_ring_free_count(tx_rings[port]));
		}
	}
	printf("=============================\n");
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(void)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Main work of application loop. 8< */
	for (;;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			/* Print out some information about the received packets. */
			printf("Core %u: Received %u packets on port %u\n",
					rte_lcore_id(), nb_rx, port);

			/* Analyze each received packet */
		 for (uint16_t i = 0; i < nb_rx; i++) {
				print_packet_info(bufs[i], port);
			}

			/* Free any unsent packets. */
			//if (unlikely(nb_tx < nb_rx)) {
			//	uint16_t buf;
			//	for (buf = nb_tx; buf < nb_rx; buf++)
			//		rte_pktmbuf_free(bufs[buf]);
			//}
			/* Free all received packets since we're not forwarding them */
			for (uint16_t i = 0; i < nb_rx; i++) {
				rte_pktmbuf_free(bufs[i]);
			}
		}
	}
	/* >8 End of loop. */
}
/* >8 End Basic forwarding application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
	unsigned lcore_id;
	uint16_t port_count = 0;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check available ports */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

	printf("Found %u Ethernet ports\n", nb_ports);

	/* Create mempool to hold the mbufs */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports and rings */
	RTE_ETH_FOREACH_DEV(portid) {
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);

		if (init_rings(portid) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init rings for port %"PRIu16 "\n", portid);

		worker_ports[port_count] = portid;
		port_count++;
	}

	/* Check if we have enough lcores for multi-threading */
	if (rte_lcore_count() < 4) {
		printf("\nWARNING: Need at least 4 lcores for full ring-based processing.\n");
		printf("Using simplified single-threaded mode.\n");
		lcore_main();
	} else {
		printf("\nUsing multi-threaded ring-based processing with %u lcores\n", rte_lcore_count());

		/* Launch workers on different lcores */
		lcore_id = rte_get_next_lcore(-1, 1, 0);
		if (port_count > 0 && lcore_id != RTE_MAX_LCORE) {
			printf("Launching RX worker for port %u on lcore %u\n", worker_ports[0], lcore_id);
			rte_eal_remote_launch(rx_worker, &worker_ports[0], lcore_id);
		}

		lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
		if (port_count > 0 && lcore_id != RTE_MAX_LCORE) {
			printf("Launching Process worker for port %u on lcore %u\n", worker_ports[0], lcore_id);
			rte_eal_remote_launch(process_worker, &worker_ports[0], lcore_id);
		}

		lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
		if (port_count > 0 && lcore_id != RTE_MAX_LCORE) {
			printf("Launching TX worker for port %u on lcore %u\n", worker_ports[0], lcore_id);
			rte_eal_remote_launch(tx_worker, &worker_ports[0], lcore_id);
		}

		/* Main core handles statistics display */
		printf("Main core %u handling statistics display\n", rte_lcore_id());

		/* Statistics display loop */
		uint64_t timer = 0;
		while (!force_quit) {
			rte_delay_ms(1000); /* Sleep for 1 second */
			timer++;

			if (timer % 10 == 0) { /* Print stats every 10 seconds */
				print_stats();
			}
		}

		/* Wait for all worker lcores to finish */
		RTE_LCORE_FOREACH_WORKER(lcore_id) {
			if (rte_eal_wait_lcore(lcore_id) < 0)
				return -1;
		}
	}

	/* Cleanup */
	printf("\nCleaning up...\n");

	/* Free rings */
	RTE_ETH_FOREACH_DEV(portid) {
		if (rx_rings[portid]) {
			rte_ring_free(rx_rings[portid]);
		}
		if (process_rings[portid]) {
			rte_ring_free(process_rings[portid]);
		}
		if (tx_rings[portid]) {
			rte_ring_free(tx_rings[portid]);
		}
	}

	/* clean up the EAL */
	rte_eal_cleanup();
	return 0;
}

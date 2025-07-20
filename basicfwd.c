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
#define RING_SIZE 1024

struct rte_ring *g_ring = NULL;
/* basicfwd.c: Basic DPDK skeleton forwarding example. */

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
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static int
rx_lcore_main(void)
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
	return 0;
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

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	//if (nb_ports < 2 || (nb_ports & 1))
	//	rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");


	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	// 初始化 DPDK ring
	g_ring = rte_ring_create("mbuf_ring", RING_SIZE, rte_socket_id(), RING_F_SC_DEQ);
	if (g_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create ring\n");

	rte_eal_remote_launch(rx_lcore_main, NULL, 0);

	rte_eal_mp_wait_lcore();			

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctp-ncsi: Transport for NC-SI over MCTP channels.
 *
 * Copyright (c) 2024 Code Construct
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <linux/mctp.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <netinet/ether.h>

static const uint8_t MCTP_TYPE_NC_SI = 0x02;
static const uint8_t MCTP_TYPE_ETHERNET = 0x03;

struct ctx {
	int tap_fd;
	int mctp_fd_ncsi;
	int mctp_fd_ethernet;
	char devname[IFNAMSIZ];
	uint8_t eid;
	unsigned int net;

	bool allow_ethernet;

	unsigned char buf[4096];
};

static int tap_init(struct ctx *ctx, const char *req_devname)
{
	struct ifreq ifr;
	int fd, rc;

	fd = open("/dev/net/tun", O_RDWR);

	if (fd < 0) {
		warn("open(/dev/net/tun)");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TAP;
	if (req_devname) {
		size_t len = strlen(req_devname);
		if (len < IFNAMSIZ)
			memcpy(ifr.ifr_name, req_devname, len);
	}

	rc = ioctl(fd, TUNSETIFF, &ifr);
	if (rc) {
		warn("ioctl(TUNSETIFF)");
		close(fd);
		return -1;
	}

	ctx->tap_fd = fd;
	strcpy(ctx->devname, ifr.ifr_name);

	return 0;
}

static int mctp_init(struct ctx *ctx)
{
	struct sockaddr_mctp addr =  {
		.smctp_family = AF_MCTP,
		.smctp_network = ctx->net,
		.smctp_addr.s_addr = MCTP_ADDR_ANY,
	};
	int fd, rc;

	fd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (fd < 0) {
		warn("Failure creating MCTP socket");
		return -1;
	}

	addr.smctp_type = MCTP_TYPE_NC_SI;
	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc) {
		warn("bind(MCTP_NCSI) failed");
		close(fd);
		return -1;
	}

	ctx->mctp_fd_ncsi = fd;

	if (!ctx->allow_ethernet)
		return 0;

	fd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (fd < 0) {
		warn("Failure creating MCTP socket");
		close(ctx->mctp_fd_ncsi);
		return -1;
	}

	addr.smctp_type = MCTP_TYPE_ETHERNET;
	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc) {
		warn("bind(MCTP_ETHERNET) failed");
		close(ctx->mctp_fd_ncsi);
		close(fd);
		return -1;
	}

	ctx->mctp_fd_ethernet = fd;

	return 0;
}

static int mctp_tx(struct ctx *ctx, uint8_t type, struct iovec *iov,
		   unsigned int n_iov)
{
	struct sockaddr_mctp addr = {
		.smctp_family = AF_MCTP,
		.smctp_network = ctx->net,
		.smctp_addr.s_addr = ctx->eid,
		.smctp_type = type,
		/* we will always be sending TO=1 messages; responses
		 * from the devices are the only case where TO=0 */
		.smctp_tag = MCTP_TAG_OWNER,
	};
	struct msghdr msg = { 0 };
	size_t exp_len = 0;
	unsigned int i;
	ssize_t tx_len;
	int fd;

	for (i = 0; i < n_iov; i++) {
		exp_len += iov[i].iov_len;
	}

	msg.msg_iov = iov;
	msg.msg_iovlen = n_iov;
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);

	fd = type == MCTP_TYPE_NC_SI ?
		ctx->mctp_fd_ncsi : ctx->mctp_fd_ethernet;

	tx_len = sendmsg(fd, &msg, 0);
	if (tx_len < 0) {
		warn("MCTP send failed");
		return -1;
	} else if ((size_t)tx_len != exp_len) {
		warnx("MCTP send truncated");
	}

	return 0;
}

static int tap_rx(struct ctx *ctx)
{
	struct iovec iov[3] = { 0 };
	struct tun_pi tunhdr;
	struct ethhdr ethhdr;
	uint16_t proto;
	ssize_t len;

	iov[0].iov_base = &tunhdr;
	iov[0].iov_len = sizeof(tunhdr);
	iov[1].iov_base = &ethhdr;
	iov[1].iov_len = sizeof(ethhdr);
	iov[2].iov_base = ctx->buf;
	iov[2].iov_len = sizeof(ctx->buf);

	len = readv(ctx->tap_fd, iov, 3);
	if (len < 0) {
		warn("recvmsg(tap)");
		return -1;
	}

	if ((size_t)len <= sizeof(tunhdr) + sizeof(ethhdr)) {
		warnx("tap rx too short");
		return 0;
	}

	proto = be16toh(tunhdr.proto);

	/* we're not sending the full buf... */
	iov[2].iov_len = len - sizeof(tunhdr) - sizeof(ethhdr);

	if (proto == ETH_P_NCSI) {
		/* MCTP message is just the data component, without
		 * the (essentially null) ethernet header */
		int rc = mctp_tx(ctx, MCTP_TYPE_NC_SI, &iov[2], 1);
		if (rc)
			return rc;
	} else if (ctx->allow_ethernet) {
		/* MCTP message is ethernet headers plus data */
		int rc = mctp_tx(ctx, MCTP_TYPE_ETHERNET, &iov[1], 2);
		if (rc)
			return rc;
	}

	return 0;
}


static int mctp_rx(struct ctx *ctx, uint8_t type)
{
	struct sockaddr_mctp addr;
	struct msghdr msg = { 0 };
	struct iovec rx_iov = { 0 }, tx_iov[3] = { 0 };
	struct tun_pi tunhdr = { .flags = 0 };
	struct ethhdr ethhdr = {
		.h_dest   = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
		.h_source = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	};
	unsigned int n_tx_iov = 0;
	uint16_t proto;
	ssize_t len;
	int fd;

	rx_iov.iov_base = ctx->buf;
	rx_iov.iov_len = sizeof(ctx->buf);

	msg.msg_iov = &rx_iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);

	fd = type == MCTP_TYPE_NC_SI ? ctx->mctp_fd_ncsi : ctx->mctp_fd_ethernet;

	len = recvmsg(fd, &msg, 0);
	if (len < 0) {
		warn("recvmsg(mctp)");
		return -1;
	}

	if (type == MCTP_TYPE_NC_SI) {
		proto = ETH_P_NCSI;
		ethhdr.h_proto = htobe16(proto);
		tunhdr.proto = proto;

		tx_iov[0].iov_base = &tunhdr;
		tx_iov[0].iov_len = sizeof(tunhdr);
		tx_iov[1].iov_base = &ethhdr;
		tx_iov[1].iov_len = sizeof(ethhdr);
		tx_iov[2].iov_base = ctx->buf;
		tx_iov[2].iov_len = len;
		n_tx_iov = 3;

	} else if (type == MCTP_TYPE_ETHERNET) {
		struct ethhdr *tmp;

		if ((size_t)len < sizeof(*tmp)) {
			warnx("invalid incoming ethernet frame, dropping");
			return -1;
		}

		/* we refer to the embedded ethernet header to populate the
		 * tun_pi's protocol field */
		tmp = (struct ethhdr *)ctx->buf;

		tunhdr.proto = tmp->h_proto;

		tx_iov[0].iov_base = &tunhdr;
		tx_iov[0].iov_len = sizeof(tunhdr);
		tx_iov[1].iov_base = ctx->buf;
		tx_iov[1].iov_len = len;
		n_tx_iov = 2;
	}

	len = writev(ctx->tap_fd, tx_iov, n_tx_iov);
	if (len < 0) {
		warn("tun write failed");
		return -1;
	}

	return 0;
}

static const struct option opts[] = {
	{ .name = "name", .has_arg = required_argument, .val = 'n' },
	{ .name = "ethernet", .has_arg = no_argument, .val = 'e'},
	{ .name = "help", .has_arg = no_argument, .val = 'h' },
	{ 0 }
};

static int parse_mctp_addr(const char *str, unsigned int *netp, uint8_t *eidp)
{
	const char *sep = strchr(str, ',');
	unsigned int net = MCTP_NET_ANY;
	unsigned long tmp;
	uint8_t eid;
	char *endp;

	if (sep) {
		errno = 0;
		tmp = strtoul(str, &endp, 10);
		if (errno || endp != sep) {
			warnx("invalid MCTP address %s", str);
			return -1;
		}

		net = tmp;
		str = sep + 1;
	}

	errno = 0;
	tmp = strtoul(str, &endp, 0);
	if (errno || endp == str || *endp != '\0') {
		warnx("invalid MCTP address %s", str);
		return -1;
	}

	/* valid MCTP address ranges.. */
	if (tmp > 0xfe || tmp < 8) {
		warnx("invalid MCTP eid %ld (0x%lx)", tmp, tmp);
	}

	eid = (uint8_t)(tmp & 0xff);

	*netp = net;
	*eidp = eid;

	return 0;
}

static void usage(const char *progname)
{
	fprintf(stderr,
		"usage: %s [--ethernet] [--name <IFNAME>] [NET,]<EID>\n",
		progname);
}

int main(int argc, char **argv)
{
	const char *req_devname = NULL;
	struct ctx _ctx, *ctx = &_ctx;
	int rc;

	for (;;) {
		int c;

		c = getopt_long(argc, argv, "hn:", opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
		case 'n':
			req_devname = optarg;
			break;
		case 'e':
			ctx->allow_ethernet = true;
			break;
		default:
			fprintf(stderr, "unknown option\n");
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "missing MCTP address argument\n");
		return EXIT_FAILURE;
	}

	rc = parse_mctp_addr(argv[optind], &ctx->net, &ctx->eid);
	if (rc)
		errx(EXIT_FAILURE, "can't parse MCTP address");

	rc = tap_init(ctx, req_devname);
	if (rc)
		errx(EXIT_FAILURE, "can't create interface");

	rc = mctp_init(ctx);
	if (rc)
		errx(EXIT_FAILURE, "can't create MCTP socket");

	printf("created tap device %s\n", ctx->devname);

	for (;;) {
		struct pollfd pollfds[] = {
			{ .fd = ctx->tap_fd, .events = POLLIN },
			{ .fd = ctx->mctp_fd_ncsi, .events = POLLIN },
			{ .fd = ctx->mctp_fd_ethernet, .events = POLLIN },
		};
		int n_pollfds = ctx->allow_ethernet ? 3 : 2;

		rc = poll(pollfds, n_pollfds, -1);
		if (rc < 0)
			err(EXIT_FAILURE, "poll()");

		if (pollfds[0].revents)
			tap_rx(ctx);

		if (pollfds[1].revents)
			mctp_rx(ctx, MCTP_TYPE_NC_SI);

		if (pollfds[2].revents)
			mctp_rx(ctx, MCTP_TYPE_ETHERNET);


	}

	return EXIT_SUCCESS;
}

// SPDX-License-Identifier: GPL-2.0
/* Userspace interface to the DMAengine memcpy throughput benchmark. */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/dmabench.h>

#define DMABENCH_PATH "/sys/kernel/debug/dmabench"

/* POSIX signal-handler communication, not kernel synchronization. */
static volatile sig_atomic_t interrupted;

static void handle_signal(int signal)
{
	interrupted = signal;
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
		"Usage: %s --channel NAME [options]\n"
		"  --channel NAME          Exact DMAengine channel name (required)\n"
		"  --transfer-size BYTES   Payload per copy (default 65536)\n"
		"  --queue-depth COUNT     Maximum outstanding copies (default 64)\n"
		"  --batch-size COUNT      Copies per issue/notification (default 16)\n"
		"  --buffer-count COUNT    Source/destination pairs (default 1024)\n"
		"  --transfers COUNT       Measured copies (default 100000)\n"
		"  --warmup-transfers N    Untimed copies (default 4096, may be 0)\n"
		"  --cpu CPU              Worker CPU (default -1, unbound)\n"
		"  --timeout-ms MS        No-progress timeout (default 3000)\n"
		"  --verify               Verify copied buffers after measurement\n"
		"  --flags MASK           Numeric flags (only bit 0: verification)\n"
		"  --json                 Print configuration and results as JSON\n"
		"  --help                 Show this help\n"
		"Numbers are decimal, without unit suffixes.\n",
		program);
}

static bool parse_u64(const char *text, uint64_t max, uint64_t *value)
{
	unsigned long long parsed;
	const char *p;
	char *end;

	if (!*text)
		return false;
	for (p = text; *p; p++)
		if (*p < '0' || *p > '9')
			return false;
	errno = 0;
	parsed = strtoull(text, &end, 10);
	if (errno || *end || parsed > max)
		return false;
	*value = parsed;
	return true;
}

static bool valid_config(const struct dmabench_config *cfg)
{
	const unsigned char *p = (const unsigned char *)cfg->channel;
	uint64_t rounded;
	long page_size;

	if (!*p)
		return false;
	for (; *p; p++)
		if (!isalnum(*p) && *p != '_' && *p != '-' && *p != '.')
			return false;
	if (!cfg->transfer_size || cfg->transfer_size > DMABENCH_MAX_TRANSFER_SIZE ||
	    !cfg->transfers || !cfg->batch_size ||
	    cfg->batch_size > cfg->queue_depth ||
	    cfg->queue_depth > cfg->buffer_count ||
	    cfg->queue_depth > DMABENCH_MAX_QUEUE_DEPTH ||
	    cfg->buffer_count > DMABENCH_MAX_BUFFER_COUNT ||
	    !cfg->timeout_ms || cfg->timeout_ms > DMABENCH_MAX_TIMEOUT_MS ||
	    cfg->flags & ~DMABENCH_F_VERIFY ||
	    cfg->transfers > UINT64_MAX / cfg->transfer_size ||
	    cfg->warmup_transfers > UINT64_MAX / cfg->transfer_size)
		return false;
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return false;
	rounded = (cfg->transfer_size + page_size - 1) / page_size * page_size;
	return rounded <= DMABENCH_MAX_ALLOCATION_BYTES / (2 * cfg->buffer_count);
}

static void print_results(const struct dmabench_run *run, bool json)
{
	const struct dmabench_config *cfg = &run->config;
	const struct dmabench_result *res = &run->result;
	double seconds = (double)res->elapsed_ns / 1e9;
	double mib = (double)res->payload_bytes / seconds / (1U << 20);
	double gib = mib / 1024;
	double tps = (double)res->completed / seconds;

	/* The validated channel alphabet needs no JSON escaping. */
	if (json) {
		printf("{\n  \"config\": {\n"
		       "    \"channel\": \"%s\",\n"
		       "    \"transfer_size\": %" PRIu64 ",\n"
		       "    \"queue_depth\": %u,\n"
		       "    \"batch_size\": %u,\n"
		       "    \"buffer_count\": %u,\n"
		       "    \"transfers\": %" PRIu64 ",\n"
		       "    \"warmup_transfers\": %" PRIu64 ",\n"
		       "    \"cpu\": %d,\n"
		       "    \"timeout_ms\": %u,\n"
		       "    \"flags\": %u\n  },\n"
		       "  \"result\": {\n"
		       "    \"elapsed_ns\": %" PRIu64 ",\n"
		       "    \"submitted\": %" PRIu64 ",\n"
		       "    \"completed\": %" PRIu64 ",\n"
		       "    \"payload_bytes\": %" PRIu64 ",\n"
		       "    \"issue_pending_calls\": %" PRIu64 ",\n"
		       "    \"allocation_bytes\": %" PRIu64 ",\n"
		       "    \"mib_per_second\": %.6f,\n"
		       "    \"gib_per_second\": %.6f,\n"
		       "    \"transactions_per_second\": %.6f\n  }\n}\n",
		       cfg->channel, (uint64_t)cfg->transfer_size, cfg->queue_depth,
		       cfg->batch_size, cfg->buffer_count, (uint64_t)cfg->transfers,
		       (uint64_t)cfg->warmup_transfers, cfg->cpu, cfg->timeout_ms,
		       cfg->flags, (uint64_t)res->elapsed_ns, (uint64_t)res->submitted,
		       (uint64_t)res->completed, (uint64_t)res->payload_bytes,
		       (uint64_t)res->issue_pending_calls,
		       (uint64_t)res->allocation_bytes, mib, gib, tps);
		return;
	}
	printf("channel=%s transfer_size=%" PRIu64
	       " queue_depth=%u batch_size=%u buffer_count=%u\n"
	       "transfers=%" PRIu64 " warmup_transfers=%" PRIu64
	       " cpu=%d timeout_ms=%u flags=%u verify=%s\n"
	       "elapsed_ns=%" PRIu64 " submitted=%" PRIu64 " completed=%" PRIu64 "\n"
	       "payload_bytes=%" PRIu64 " issue_pending_calls=%" PRIu64
	       " allocation_bytes=%" PRIu64 "\n"
	       "Payload throughput: %.3f MiB/s, %.3f GiB/s, %.3f transactions/s\n",
	       cfg->channel, (uint64_t)cfg->transfer_size, cfg->queue_depth,
	       cfg->batch_size, cfg->buffer_count, (uint64_t)cfg->transfers,
	       (uint64_t)cfg->warmup_transfers, cfg->cpu, cfg->timeout_ms,
	       cfg->flags, cfg->flags & DMABENCH_F_VERIFY ? "yes" : "no",
	       (uint64_t)res->elapsed_ns, (uint64_t)res->submitted,
	       (uint64_t)res->completed, (uint64_t)res->payload_bytes,
	       (uint64_t)res->issue_pending_calls, (uint64_t)res->allocation_bytes,
	       mib, gib, tps);
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{ "channel", required_argument, NULL, 'c' },
		{ "transfer-size", required_argument, NULL, 's' },
		{ "queue-depth", required_argument, NULL, 'q' },
		{ "batch-size", required_argument, NULL, 'b' },
		{ "buffer-count", required_argument, NULL, 'p' },
		{ "transfers", required_argument, NULL, 't' },
		{ "warmup-transfers", required_argument, NULL, 'w' },
		{ "cpu", required_argument, NULL, 'a' },
		{ "timeout-ms", required_argument, NULL, 'm' },
		{ "verify", no_argument, NULL, 'v' },
		{ "flags", required_argument, NULL, 'f' },
		{ "json", no_argument, NULL, 'j' },
		{ "help", no_argument, NULL, 'h' },
		{ }
	};
	struct dmabench_run run = {
		.config = {
			.transfer_size = 65536,
			.queue_depth = 64,
			.batch_size = 16,
			.buffer_count = 1024,
			.transfers = 100000,
			.warmup_transfers = 4096,
			.cpu = -1,
			.timeout_ms = 3000,
		},
	};
	struct dmabench_config *cfg = &run.config;
	struct sigaction action = { .sa_handler = handle_signal };
	bool json = false;
	int opt, fd;

	while ((opt = getopt_long(argc, argv, "", options, NULL)) != -1) {
		uint64_t value, max;

		switch (opt) {
		case 'h':
			usage(stdout, argv[0]);
			return EXIT_SUCCESS;
		case 'c':
			if (!*optarg || strlen(optarg) >= sizeof(cfg->channel))
				goto invalid;
			strcpy(cfg->channel, optarg);
			continue;
		case 'v':
			cfg->flags |= DMABENCH_F_VERIFY;
			continue;
		case 'j':
			json = true;
			continue;
		case 'a':
			if (!strcmp(optarg, "-1")) {
				cfg->cpu = -1;
				continue;
			}
			break;
		case '?':
			usage(stderr, argv[0]);
			return EXIT_FAILURE;
		}
		max = opt == 's' || opt == 't' || opt == 'w' ? UINT64_MAX :
			opt == 'a' ? INT_MAX : UINT32_MAX;
		if (!parse_u64(optarg, max, &value))
			goto invalid;
		switch (opt) {
		case 's':
			cfg->transfer_size = value;
			break;
		case 'q':
			cfg->queue_depth = value;
			break;
		case 'b':
			cfg->batch_size = value;
			break;
		case 'p':
			cfg->buffer_count = value;
			break;
		case 't':
			cfg->transfers = value;
			break;
		case 'w':
			cfg->warmup_transfers = value;
			break;
		case 'a':
			cfg->cpu = value;
			break;
		case 'm':
			cfg->timeout_ms = value;
			break;
		case 'f':
			cfg->flags = value;
			break;
		}
	}
	if (optind != argc || !valid_config(cfg)) {
		fprintf(stderr,
			"Invalid configuration: require a channel and valid resource limits; see --help.\n");
		return EXIT_FAILURE;
	}

	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL) ||
	    sigaction(SIGTERM, &action, NULL) ||
	    sigaction(SIGHUP, &action, NULL)) {
		perror("sigaction");
		return EXIT_FAILURE;
	}
	fd = open(DMABENCH_PATH, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("open " DMABENCH_PATH);
		return EXIT_FAILURE;
	}
	if (interrupted) {
		fprintf(stderr, "dmabench interrupted before starting\n");
		close(fd);
		return EXIT_FAILURE;
	}
	/* EINTR is final: never restart a benchmark automatically. */
	if (ioctl(fd, DMABENCH_RUN, &run) < 0) {
		perror("DMABENCH_RUN");
		close(fd);
		return EXIT_FAILURE;
	}
	close(fd);
	if (!run.result.elapsed_ns || run.result.completed != cfg->transfers ||
	    run.result.submitted != cfg->transfers) {
		fprintf(stderr, "DMABENCH_RUN returned invalid results\n");
		return EXIT_FAILURE;
	}
	print_results(&run, json);
	return EXIT_SUCCESS;

invalid:
	fprintf(stderr, "Invalid option value: %s\n", optarg);
	return EXIT_FAILURE;
}

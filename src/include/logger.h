#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>


// Logger levels
#define LOGLVL_CRITICAL	  4
#define LOGLVL_ERROR	  3
#define LOGLVL_WARNING	  2
#define LOGLVL_INFO		  1
#define LOGLVL_DEBUG	  0

// logger structure
#ifdef  MAIN_FILE
int logLevel;
FILE *logFacility;
FILE *logErrorFacility;
#else
extern int logLevel;
extern FILE *logFacility, *logErrorFacility;
#endif

#define init_logger(...) do { \
		logLevel = LOGLVL_WARNING; \
		logFacility = stdout; \
		logErrorFacility = stderr; \
		setbuf(logFacility, NULL); \
		setbuf(logErrorFacility, NULL); \
	} while(0)


// logger functions
#define logger_print(...) do { \
	fprintf(logFacility, __VA_ARGS__); \
	} while(0)

#define logger_print_error(...) do { \
	fprintf(logErrorFacility, __VA_ARGS__); \
	} while(0)

#define log_critical(...) do { \
	if (logLevel <= LOGLVL_CRITICAL) { \
		logger_print_error(__VA_ARGS__); \
	} } while(0)

#define log_error(...) do { \
	if (logLevel <= LOGLVL_ERROR) { \
		logger_print_error(__VA_ARGS__); \
	} } while(0)

#define log_warning(...) do { \
	if (logLevel <= LOGLVL_WARNING) { \
		logger_print(__VA_ARGS__); \
	} } while(0)

#define log_info(...) do { \
	if (logLevel <= LOGLVL_INFO) { \
		logger_print(__VA_ARGS__); \
	} } while(0)

#define log_debug(...) do { \
	if (logLevel <= LOGLVL_DEBUG) { \
		logger_print(__VA_ARGS__); \
	} } while(0)

#define logger_pkt(buf, len) do { \
	printf("|"); \
	int _i_, _j_; \
	unsigned char _c_; \
	for (_i_=0; _i_<(len); _i_++){ \
		if (_i_ % 16 == 0 && _i_ > 0) { \
			printf("|    |"); \
			for (_j_=0; _j_<16; _j_++) { \
				if (_j_ == 8) \
					printf(" "); \
				_c_ = ((unsigned char *)(buf))[_i_-16+_j_]; \
				if (_c_ >= 0x20 && _c_ < 0x7f) \
					printf("%c", _c_); \
				else \
					printf("."); \
			} \
			printf("|\n|"); \
		} else if (_i_ % 8 == 0 && _i_ > 0) \
			printf("  "); \
		else if (_i_ != 0) \
			printf(" "); \
		printf("%02x", ((unsigned char *)(buf))[_i_]); \
	} \
	for (_j_=0; _j_<16*3-(_i_%16)*3+(_i_%16>8?0:1); _j_++) { \
		printf(" "); \
	} \
	printf("|    |"); \
	for (int _j_=0; _j_<=((_i_-1)%16); _j_++) { \
		if (_j_ == 8) \
			printf(" "); \
		_c_ = ((unsigned char *)(buf))[_i_-16+_j_]; \
		if (_c_ >= 0x20 && _c_ < 0x7f) \
			printf("%c", _c_); \
		else \
			printf("."); \
	} \
	for (_j_=0; _j_<16-(_i_%16)+(_i_%16>8?0:1); _j_++) { \
		printf(" "); \
	} \
	printf("|\n"); \
} while(0)

#define log_pkt_debug(buf, len) do { \
	if (logLevel <= LOGLVL_DEBUG) { \
		logger_pkt((buf), (len)); \
	} } while(0)


#endif /* LOG_H */

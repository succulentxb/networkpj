#include <time.h>
#include "grading.h"


#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1

#define SIZE32 4
#define SIZE16 2
#define SIZE8  1

#define NO_FLAG 0
#define NO_WAIT 1
#define TIMEOUT 2

#define TRUE 1
#define FALSE 0

typedef struct {
	uint32_t expected_rev_seq;
	uint32_t last_ack_received;
	pthread_mutex_t ack_lock;
	uint32_t last_send_base;
	int need_ack;
} window_t;

typedef struct {
	int socket;   

	pthread_t thread_id;

	uint16_t my_port;
	uint16_t their_port;
	struct sockaddr_in conn;

	char* received_buf;
	int received_len;
	pthread_mutex_t recv_lock;

	pthread_cond_t wait_cond;
	pthread_cond_t close_wait_cond;

	char* tmp_buf;
	uint32_t tmp_len;
	char* sending_buf;
	int sending_len;
	int type;
	pthread_mutex_t send_lock;

	int dying;
	pthread_mutex_t death_lock;

	window_t window;

	uint32_t rwnd;
    uint32_t cwnd;

	struct timeval send_time;
	struct timeval recv_time;
	int edit_time_flag;
	pthread_mutex_t time_lock;

	int their_fin;
	int their_syn;
	int my_fin;

	uint32_t esti_rtt;
    uint32_t samp_rtt;
    uint32_t dev_rtt;
    struct timeval timeout_interval;

    int dup_ack;
    int status;
    uint32_t ssthresh;

    uint32_t wmax;
} cmu_socket_t;

#endif

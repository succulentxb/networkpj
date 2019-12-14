#ifndef _CMU_BACK_H_

#define _CMU_BACK_H_
#define MSS MAX_DLEN

#include "cmu_tcp.h"
#include "global.h"
#include "cmu_packet.h"

int check_ack(cmu_socket_t * dst, uint32_t seq);
void check_for_data(cmu_socket_t * dst, int flags);
void * begin_backend(void * in);
void flag_pkt_rdt_send(cmu_socket_t* sock, int seq, int ack, uint8_t flags);

#endif

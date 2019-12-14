#include <time.h>

#include "backend.h"

void flag_pkt_rdt_send(cmu_socket_t* sock, int seq, int ack, uint8_t flags);

int check_for_data_inner(cmu_socket_t * sock, int flags);

//发送指定数据
void send_datas(cmu_socket_t *sock, char *data, int buf_len, uint32_t seq_from);

//发送ACK
void send_ack(cmu_socket_t *sock,uint32_t ack_num);
void handle_message(cmu_socket_t * sock, char* pkt);

//获取流量控制窗口大小
uint32_t get_rwnd(cmu_socket_t * sock);

//获取拥塞控制窗口大小
uint32_t get_cwnd(cmu_socket_t * sock);

//修改拥塞控制窗口大小
void update_cc_state(cmu_socket_t * sock,int reason);
int check_ack(cmu_socket_t * sock, uint32_t seq);
void update_timer(cmu_socket_t *sock);

//根据send_base重发数据包
void re_send(cmu_socket_t * sock);

//获取最小的窗口大小
uint32_t get_min_window_size(cmu_socket_t *sock);

//开始发送
void begin_send(cmu_socket_t *sock);
uint32_t get_adv_window(cmu_socket_t *sock);

//修改流量窗口大小
void edit_rwnd(cmu_socket_t * sock,uint32_t size);

//修改cwnd  的原因
#define NEW_ACK 0
#define DUP_ACK 1
#define DELAY 2

//拥塞控制状态
#define SLOW_START 0
#define CONGESTION_AVOIDANCE 1
#define FAST_RECOVERY 2


//修改流量窗口大小
void edit_rwnd(cmu_socket_t * sock,uint32_t size) {
    //printf("edit rwnd = %d\n", size);
    sock->rwnd = size;
}
//获取流量控制窗口大小
uint32_t get_rwnd(cmu_socket_t * sock) {
    return sock->rwnd;
}
//获取拥塞控制窗口大小
uint32_t get_cwnd(cmu_socket_t * sock) {
    return sock->cwnd;
}

/**
 * Param: sock - tcp socket to be update
 * Param: sign - the sign to trigger different update action
 * 
 * Purpose: To update tcp socket congestion controll state.
 *  These signs involve NEW_ACK(normal ack), DELAY(timeout), DUP_ACK(duplicated ack).
*/
void update_cc_state(cmu_socket_t * sock, int sign) {
    switch (sign) {
      case NEW_ACK:
        sock->dup_ack = 0;
        if (sock->status == SLOW_START) {
          sock->cwnd = sock->cwnd + MSS;
          if (sock->cwnd > sock->ssthresh)
            sock->status = CONGESTION_AVOIDANCE;
          return;
        }
        if (sock->status == CONGESTION_AVOIDANCE) {
          if (sock->cwnd == 0)
            sock->cwnd = MSS;
          sock->cwnd = sock->cwnd + MSS*(MSS / sock->cwnd);            
          return;
        }
        if (sock->status == FAST_RECOVERY) {
          sock->cwnd = sock->ssthresh;
          sock->status = CONGESTION_AVOIDANCE;
          return;
        }
        break;
      
      case DELAY:
        sock->ssthresh = sock->cwnd/2;
        sock->cwnd = MSS;
        sock->dup_ack = 0;
        sock->status = SLOW_START;
        // timeout resend in begin_backend()
        return;

      case DUP_ACK:
        if (sock->status == FAST_RECOVERY) {
          sock->cwnd = sock->cwnd + MSS;
          re_send(sock);
          return;
        }
        sock->dup_ack++;
        if (sock->dup_ack == 3) {
          sock->ssthresh = sock->cwnd/2;
          sock->cwnd = sock->ssthresh + 3*MSS;
          sock->status = FAST_RECOVERY;
          re_send(sock);          
        }
        break;
    }
    return;
}

/**
 * Param: sock - The socket to get advertised window size.
 * 
 * Purpose: Get advertised window size of the socket this side.
 *  Window size is the remain buffer size.
 * 
 * Return: return adv_window
*/
uint32_t get_adv_window(cmu_socket_t* sock) {
    uint32_t receive_len = sock->received_len;
    if (MAX_NETWORK_BUFFER - receive_len >= MAX_NETWORK_BUFFER)
      return MAX_NETWORK_BUFFER-1;
    else
      return MAX_NETWORK_BUFFER - receive_len;
}

uint32_t get_min_window_size(cmu_socket_t *sock) {
    uint32_t min_window;
    min_window = get_rwnd(sock) < get_cwnd(sock)? get_rwnd(sock):get_cwnd(sock);
    if (min_window <= 0)
      return 1;
    return min_window;
}


/**
 * Param: sock - tcp socket to be update
 * 
 * Purpose: Update socket timer according to packet transfer time.
*/
void update_timer(cmu_socket_t *sock) {
  if (!sock->edit_time_flag)
    return;

  sock->samp_rtt = (sock->recv_time.tv_sec-sock->send_time.tv_sec)*1000000 + (sock->recv_time.tv_usec-sock->send_time.tv_usec);
  sock->esti_rtt = 0.875*sock->esti_rtt + 0.125*sock->samp_rtt;
  sock->dev_rtt = 0.75*sock->dev_rtt + 0.25*abs(sock->samp_rtt-sock->esti_rtt);
  sock->timeout_interval.tv_sec = (sock->esti_rtt + 4*sock->dev_rtt)/1000000;
  sock->timeout_interval.tv_usec = (sock->esti_rtt + 4*sock->dev_rtt)%1000000;
}

int is_timeout(cmu_socket_t *sock,struct timeval * time1,struct timeval *time2) {
  //puts("is_timeout");
  uint32_t t1 = (time2->tv_sec - time1->tv_sec)*1000000 + (time2->tv_usec - time1->tv_usec);
  uint32_t t2 = sock->timeout_interval.tv_sec * 1000000 + sock->timeout_interval.tv_usec;
  if (t1 > t2)
    return 1;
  else 
    return 0;
}
/*
 * Param: sock - The socket to check for acknowledgements. 
 * Param: seq - Sequence number to check 
 *
 * Purpose: To tell if a packet (sequence number) has been acknowledged.
 */
int check_ack(cmu_socket_t * sock, uint32_t seq) {
  int result;
  while(pthread_mutex_lock(&(sock->window.ack_lock)) != 0);
  if(sock->window.last_ack_received >= seq)
    result = TRUE;
  else
    result = FALSE;
  pthread_mutex_unlock(&(sock->window.ack_lock));
  return result;
}

/**
 * Param: sock - The sock to send ack.
 * Param: ack - Ack number.
 * 
 * Purpose: Send an ack packet.
*/
void send_ack(cmu_socket_t* sock, uint32_t ack) {
    char* pkt;
    socklen_t conn_len = sizeof(sock->conn); 
    uint32_t adv_window = get_adv_window(sock);

    pkt = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), 0, ack, 
        DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, adv_window, 0, NULL, NULL, 0);
    sendto(sock->socket, pkt, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) &(sock->conn), conn_len);
    free(pkt);
}

/**
 * Param: sock - tcp socket to send flag
 * Param: seq - packet seq to send
 * Param: ack - packet ack to send
 * Param: flags - packet flags, include SYN_FLAG_MASK, ACK_FLAG_MASK, FIN_FLAG_MASK
 * 
 * Purpose: Send packet which only contains packet header with flags info.
 *  Design to be used for tcp connection shakehands or wavehands.
 *  Packet will be sent by a reliable data transfer pipe.
*/
void flag_pkt_rdt_send(cmu_socket_t* sock, int seq, int ack, uint8_t flags) {
    char* pkt;
    socklen_t conn_len = sizeof(sock->conn); 
    uint32_t adv_window = get_adv_window(sock);

    pkt = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq, ack, 
        DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, flags, adv_window, 0, NULL, NULL, 0);

    while(TRUE) {
      sendto(sock->socket, pkt, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) &(sock->conn), conn_len);
      check_for_data(sock, TIMEOUT);
      if (check_ack(sock, seq+1)) {
        if (!(flags & SYN_FLAG_MASK) || sock->their_syn)
          break;
      }
    }  
    free(pkt); 
}

/*
 * Param: sock - The socket used for handling packets received
 * Param: pkt - The packet data received by the socket
 *
 * Purpose: Updates the socket information to represent
 *  the newly received packet.
 *
 */
void handle_message(cmu_socket_t * sock, char* pkt) {
    uint8_t flags = get_flags(pkt);
    uint32_t seq = get_seq(pkt);
    uint32_t data_len;
    socklen_t conn_len = sizeof(sock->conn);

    // response ACK when recieve FIN
    if (flags & FIN_FLAG_MASK) {
      sock->their_fin = TRUE;
      send_ack(sock, seq+1);
      return;
    }

    // response SYN
    if (flags & SYN_FLAG_MASK) {
      sock->their_syn = TRUE;

      // It does not matter with lock because it is processing handshake.
      while(pthread_mutex_lock(&(sock->window.ack_lock)) != 0);
      sock->window.expected_rev_seq = get_seq(pkt)+1;
      pthread_mutex_unlock(&(sock->window.ack_lock));

      if(flags & ACK_FLAG_MASK) {
        while(pthread_mutex_lock(&(sock->window.ack_lock)) != 0);
        sock->window.last_ack_received = get_ack(pkt);
        pthread_mutex_unlock(&(sock->window.ack_lock));
        send_ack(sock, seq+1);
      }
      return;
    }

    // response ACK
    if (flags & ACK_FLAG_MASK) {
      sock->rwnd = get_advertised_window(pkt);

      // duplicated ack
      if (get_ack(pkt) == sock->window.last_ack_received) {
        update_cc_state(sock, DUP_ACK);        
      }
      // normal ack
      if(get_ack(pkt) > sock->window.last_ack_received) {
        gettimeofday(&sock->recv_time, NULL);
        update_timer(sock);
        sock->window.last_ack_received = get_ack(pkt);
        update_cc_state(sock, NEW_ACK);
      }
    }


    // send duplicated ack and expected seq when recieve unexpected seq
    if (seq != sock->window.expected_rev_seq && sock->window.expected_rev_seq > 0 ) {
        send_ack(sock, sock->window.expected_rev_seq);
        return;
    }

    // normal seq to get
    if(seq == sock->window.expected_rev_seq) {
      while(pthread_mutex_lock(&(sock->recv_lock)) != 0);

      data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
      sock->window.expected_rev_seq = seq + data_len; 
      if(sock->received_buf == NULL) {
          sock->received_buf = malloc(data_len);
      }
      else{
          sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len);
      }
      memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN, data_len);
      sock->received_len += data_len;

      pthread_mutex_unlock(&(sock->recv_lock));

      send_ack(sock, seq+data_len);
    }
}

/*
 * Param: sock - The socket used for receiving data on the connection.
 * Param: flags - Signify different checks for checking on received data.
 *  These checks involve no-wait, wait, and timeout.
 *
 * Purpose: To check for data received by the socket. 
 *
 */
void check_for_data(cmu_socket_t* sock, int flags) {
  check_for_data_inner(sock, flags);
}

int check_for_data_inner(cmu_socket_t* sock, int flags) {
  char hdr[DEFAULT_HEADER_LEN];
  char* pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;
  fd_set ackFD;
  struct timeval time_out;
  time_out.tv_sec = 3;
  time_out.tv_usec = 0;
  int total_len = 0;


  while(pthread_mutex_lock(&(sock->recv_lock)) != 0);
  switch(flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_PEEK,
                (struct sockaddr *) &(sock->conn), &conn_len);
      break;

    case TIMEOUT:
      FD_ZERO(&ackFD);
      FD_SET(sock->socket, &ackFD);
      time_out = sock->timeout_interval;
      if(select(sock->socket+1, &ackFD, NULL, NULL, &time_out) <= 0) {
        break;
      }

    case NO_WAIT:
      len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK, 
          (struct sockaddr*) &(sock->conn), &conn_len);
      break;

    default:
      perror("[ERROR] unknown flag");
      return 0;
  }
  
  total_len = len;
  while(len >= DEFAULT_HEADER_LEN) {
    plen = get_plen(hdr);
    pkt = malloc(plen);
    buf_size = 0;
    while(buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 
          NO_FLAG, (struct sockaddr*) &(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);

    // recieve new coming
    len = 0;
    len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
               (struct sockaddr *) &(sock->conn), &conn_len); 
    total_len = total_len + len;
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return total_len;
}

//发送数据
void send_datas(cmu_socket_t *sock, char *data, int buf_len, uint32_t seq_from) {
  //puts("send_datas");
  char* msg;
  char* data_offset = data;
  int sockfd, plen;
  size_t conn_len = sizeof(sock->conn);
  uint32_t seq = seq_from;
  uint32_t adv_window = get_adv_window(sock);
  sockfd = sock->socket;

  if(buf_len > 0) {
    while(buf_len != 0) {
      if(buf_len <= MAX_DLEN) {
        plen = DEFAULT_HEADER_LEN + buf_len;
        msg = create_packet_buf(sock->my_port, sock->their_port, seq, 0, DEFAULT_HEADER_LEN, plen, NO_FLAG, adv_window, 0, NULL, data_offset, buf_len);
        buf_len = 0;
        seq = seq + buf_len;
      }
      else{
        plen = DEFAULT_HEADER_LEN + MAX_DLEN;
        msg = create_packet_buf(sock->my_port, sock->their_port, seq, 0, DEFAULT_HEADER_LEN, plen, NO_FLAG, adv_window, 0, NULL, data_offset, MAX_DLEN);
        buf_len -= MAX_DLEN;
        seq = seq + MAX_DLEN;
      }
      sendto(sockfd, msg, plen, 0, (struct sockaddr*) &(sock->conn), conn_len);
      free(msg);
      data_offset = data_offset + plen - DEFAULT_HEADER_LEN;
    }
  }
}
//收到三次冗余ACK重发
void re_send(cmu_socket_t * sock) {
    //puts("re_send");
    if (sock->temp_data == NULL)
      return;
    sock->edit_time_flag = FALSE;
    uint32_t send_base = sock->window.last_ack_received;
    uint32_t min_window = get_min_window_size(sock);
    uint32_t have_sent_size = (sock->window.last_ack_received - sock->window.last_send_base);
    uint32_t send_size = sock->temp_data_size - have_sent_size < min_window ? sock->temp_data_size - have_sent_size : min_window;
    //printf("temp_data = %p send_size = %d \n", sock->temp_data,send_size);
    send_datas(sock,sock->temp_data+have_sent_size,send_size,send_base);
}
//开始发送数据
void begin_send(cmu_socket_t * sock) {
    //puts("begin_send");
    uint32_t min_window;
    sock->edit_time_flag = TRUE;
    while (TRUE) {
        sock->window.last_send_base = sock->window.last_ack_received;
        min_window = get_min_window_size(sock);
        while(pthread_mutex_lock(&(sock->send_lock)) != 0);
        uint32_t buf_len = sock->sending_len;  
        if (sock->temp_data_size < min_window && buf_len != 0) {
            //printf("temp_data_size = %d min_window = %d buf_len = %d last_send_base = %d\n", sock->temp_data_size,min_window,buf_len,sock->window.last_send_base);
            sock->temp_data = realloc(sock->temp_data,min_window);
            uint32_t add_size = (min_window - sock->temp_data_size) < buf_len ? (min_window - sock->temp_data_size): buf_len;
            sock->temp_data_size = sock->temp_data_size + add_size;
            memcpy(sock->temp_data,sock->sending_buf,add_size);
            uint32_t left_size = buf_len - add_size;
            char * left_data = calloc(buf_len - add_size,1);
            memcpy(left_data,sock->sending_buf + add_size, buf_len - add_size);
            free(sock->sending_buf);
            sock->sending_buf = left_data;
            sock->sending_len = left_size;
        }
        pthread_mutex_unlock(&(sock->send_lock));
        if (sock->temp_data_size <= 0) {
          break;
        }
        gettimeofday(&sock->send_time,NULL);
        
        struct timeval time1;
        struct timeval time2;
        gettimeofday(&time1,NULL);
        send_datas(sock,sock->temp_data,sock->temp_data_size,sock->window.last_ack_received);
        while (TRUE) {
          check_for_data(sock, TIMEOUT);
          gettimeofday(&time2,NULL);
          if (sock->window.last_ack_received > sock->window.last_send_base)
            break;
          if (is_timeout(sock,&time1,&time2)) {
              sock->edit_time_flag = FALSE;
 
              update_cc_state(sock,DELAY);
              break;
          }
        }
        int have_sent_size = (sock->window.last_ack_received - sock->window.last_send_base);
        sock->temp_data_size = sock->temp_data_size - have_sent_size;
        if (sock->temp_data_size == 0)
          sock->edit_time_flag = TRUE;
        char * new_data = malloc(sock->temp_data_size);
        memcpy(new_data,sock->temp_data + have_sent_size,sock->temp_data_size);
        free(sock->temp_data);
        sock->temp_data = new_data;
    }
    free(sock->temp_data);
    sock->edit_time_flag = FALSE;
    sock->temp_data_size = 0;
    sock->temp_data = NULL;
}
/*
 * Param: in - the socket that is used for backend processing
 *
 * Purpose: To poll in the background for sending and receiving data to
 *  the other side. 
 *
 */
void* begin_backend(void * in) {
  //puts("backend");
  cmu_socket_t * dst = (cmu_socket_t *) in;

  int death, buf_len, send_signal;
  char* data;

  while(TRUE) {
    while(pthread_mutex_lock(&(dst->death_lock)) !=  0);
    death = dst->dying;
    pthread_mutex_unlock(&(dst->death_lock));
    
    
    while(pthread_mutex_lock(&(dst->send_lock)) != 0);
    buf_len = dst->sending_len;
    pthread_mutex_unlock(&(dst->send_lock));
    //printf("backend temp_data_size = %d  rwnd = %d cwnd = %d buf_len = %d recv_len = %d ,mydying = %d their_fin = %d last_ack_received = %d \n", dst->temp_data_size,get_rwnd(dst),get_cwnd(dst),buf_len,dst->recv,dst->my_fin,dst->their_fin,dst->window.last_ack_received);
    //如果自己的buf_len 等于0 并且接到对方的fin 且发的fin 被接到了，那么停下来等待一段时间
    if(death && buf_len == 0 && dst->their_fin  && dst->my_fin) {
      puts("thread wait to exit");
      while (TRUE) {
          //设置时间为2 * Maximum segment lifetime
          dst->timeout_interval.tv_sec = 10 * dst->timeout_interval.tv_sec;
          dst->timeout_interval.tv_usec = 10 * dst->timeout_interval.tv_usec;
          if (check_for_data_inner(dst,TIMEOUT) == 0)
            break;
      }
      //puts("thread  exit");
      
      break;
    }

    if(buf_len > 0) {
      //printf("sending_buf = %d\n", dst->sending_len);
      begin_send(dst); 
      //pthread_mutex_unlock(&(dst->send_lock));
    }
    while(pthread_mutex_lock(&(dst->send_lock)) != 0);
    buf_len = dst->sending_len;
    pthread_mutex_unlock(&(dst->send_lock));

    if (buf_len == 0 && dst->temp_data_size == 0 && dst->dying) {
        pthread_cond_signal(&(dst->close_wait_cond)); 
    }
        

    check_for_data(dst, NO_WAIT);
    
    while(pthread_mutex_lock(&(dst->recv_lock)) != 0);
    
    if(dst->received_len > 0 || dst->their_fin)
      send_signal = TRUE;
    else
      send_signal = FALSE;
    pthread_mutex_unlock(&(dst->recv_lock));
    
    if(send_signal) {
      pthread_cond_signal(&(dst->wait_cond));  
    }
  }


  pthread_exit(NULL); 
  return NULL; 
}

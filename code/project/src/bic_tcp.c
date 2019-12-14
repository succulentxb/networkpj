#include <time.h>

#include "backend.h"

//发送指定数据
void send_datas(cmu_socket_t *sock, char *data, int buf_len, uint32_t seq_from);

//发送ACK
void send_ack(cmu_socket_t *sock,uint32_t ack_num);

//处理接收的数据
void handle_message(cmu_socket_t * sock, char* pkt);

//获取流量控制窗口大小
uint32_t get_rwnd(cmu_socket_t * sock);

//获取拥塞控制窗口大小
uint32_t get_cwnd(cmu_socket_t * sock);

//修改拥塞控制窗口大小
void update_cc_state(cmu_socket_t * sock,int reason);

//检查ack 是否收到
int check_ack(cmu_socket_t * sock, uint32_t seq);

//修改超时间隔
void edit_timer(cmu_socket_t *sock);

//根据send_base重发数据包
void resend(cmu_socket_t * sock);

//获取最小的窗口大小
uint32_t get_min_window_size(cmu_socket_t *sock);

//开始发送
void begin_send(cmu_socket_t *sock);

//获取当前剩余的缓存大小
uint32_t get_my_adv_window(cmu_socket_t *sock);

//修改流量窗口大小
void edit_rwnd(cmu_socket_t * sock,uint32_t size);

//修改cwnd  的原因
#define NEW_ACK 0
#define DUPLICATE_ACK 1
#define DELAY 2

//拥塞控制状态
#define MAX_PROBE 0
#define NORMAL 1



//修改流量窗口大小
void edit_rwnd(cmu_socket_t * sock,uint32_t size){
    //printf("edit rwnd = %d\n", size);
    sock->rwnd = size;
}
//获取流量控制窗口大小
uint32_t get_rwnd(cmu_socket_t * sock){
    return sock->rwnd;
}
//获取拥塞控制窗口大小
uint32_t get_cwnd(cmu_socket_t * sock){
    return sock->cwnd;
}

//修改cwnd,原因有：TIMEOUT 和 收到三个冗余ack,收到正常的ACK
void update_cc_state(cmu_socket_t * sock,int reason){
    switch (reason){
      case DUPLICATE_ACK:
         sock->dup_ack++;
         if (sock->dup_ack == 3){
              sock->dup_ack = 0;
              resend(sock);          
         }
         break;
      case DELAY:
              sock->wmax = sock->cwnd;
              sock->cwnd = sock->cwnd /2 < MSS ? MSS:sock->cwnd /2;
              sock->dup_ack = 0;
              sock->status = NORMAL;
              //超时重传实现在begin_send 中
              return;
          
         break;
      case NEW_ACK:
          sock->dup_ack = 0;
          if (sock->status == NORMAL){
              sock->cwnd = (sock->cwnd + sock->wmax)/2 + MSS;
              if (sock->cwnd > sock->wmax)
                sock->status = MAX_PROBE;
              return;
          }
          if (sock->status == MAX_PROBE){
              sock->cwnd = sock->cwnd + MSS;            
              return;
          }
         break;
    }
    return;
}

uint32_t get_my_adv_window(cmu_socket_t *sock){
    uint32_t receive_len = sock->received_len;
    if (MAX_NETWORK_BUFFER - receive_len >= 65536)
      return 65535;
    else
      return MAX_NETWORK_BUFFER - receive_len;
}

uint32_t get_min_window_size(cmu_socket_t *sock){
    uint32_t min_window;
    min_window = get_rwnd(sock) < get_cwnd(sock)? get_rwnd(sock):get_cwnd(sock);
    if (min_window <= 0)
      return 1;
    return min_window;
}
void edit_timer(cmu_socket_t *sock){

    if (!sock->edit_time_flag)
      return;

    sock->samp_rtt = (sock->recv_time.tv_sec - sock->send_time.tv_sec)*1000000 + (sock->recv_time.tv_usec - sock->send_time.tv_usec); 
    sock->esti_rtt = 0.875*sock->esti_rtt + 0.125*sock->samp_rtt;
    sock->dev_rtt = 0.75*sock->dev_rtt + 0.25*abs(sock->samp_rtt - sock->esti_rtt);
    sock->timeout_interval.tv_sec = (sock->esti_rtt + 4 * sock->dev_rtt)/1000000;
    sock->timeout_interval.tv_usec = (sock->esti_rtt + 4 * sock->dev_rtt)%1000000;
}
int is_timeout(cmu_socket_t *sock,struct timeval * time1,struct timeval *time2){
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
 *
 */
int check_ack(cmu_socket_t * sock, uint32_t seq){
  int result;
  while(pthread_mutex_lock(&(sock->window.ack_lock)) != 0);
  if(sock->window.last_ack_received >= seq)
    result = TRUE;
  else
    result = FALSE;
  pthread_mutex_unlock(&(sock->window.ack_lock));
  return result;
}
//发送ACK
void send_ack(cmu_socket_t *sock,uint32_t ack_num){
    //printf("send ack = %d\n", ack_num);
    char* rsp;
    socklen_t conn_len = sizeof(sock->conn); 
    uint32_t adv_window = get_my_adv_window(sock);

    rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), 0, ack_num, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, adv_window, 0, NULL, NULL, 0);
    sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) &(sock->conn), conn_len);
    free(rsp);
}
/*
 * Param: sock - The socket used for handling packets received
 * Param: pkt - The packet data received by the socket
 *
 * Purpose: Updates the socket information to represent
 *  the newly received packet.
 *
 * Comment: This will need to be updated for checkpoints 1,2,3
 *
 */
void reliable_flags_packet_send(cmu_socket_t * sock,int seq,int ack,uint8_t flags){
    char pkt[DEFAULT_HEADER_LEN];
    char* rsp;
    uint32_t len;
    socklen_t conn_len_for_send;
    conn_len_for_send = sizeof(sock->conn); 
    uint32_t adv_window = get_my_adv_window(sock);
    rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq, ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, flags, adv_window, 0, NULL, NULL, 0);
    while(TRUE){
        puts("send flags");
        sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) &(sock->conn), conn_len_for_send);
        check_for_data(sock, TIMEOUT);
        //printf("seq = %d last_ack_received = %d result = %d\n", seq ,sock->window.last_ack_received,result);
        if (check_ack(sock,seq+1) == TRUE){
            //printf("seq = %d last_ack_received = %d\n",seq,sock->window.last_ack_received);
            //如果发送的包不是syn则结束
            if ((flags & SYN_FLAG_MASK) == 0)
              break;
            //如果是syn, 但是收到了对方的syn,则结束
            if (sock->their_syn)
              break;
        }
           
        
    }  
    free(rsp); 
}
//处理接收的数据
void handle_message(cmu_socket_t * sock, char* pkt){

    uint8_t flags = get_flags(pkt);
    uint32_t data_len, seq;
    socklen_t conn_len = sizeof(sock->conn);
    //获取包的序号
    seq = get_seq(pkt);
    printf("seq = %d ack = %d flags = %d \n",seq, get_ack(pkt),flags);
    
    //收到fin 回ack 
    if (flags & FIN_FLAG_MASK){
      puts("recv fin!");
      printf("mydying = %d\n",sock->dying );
      printf("ack = %d\n", seq + 1);
      sock->their_fin = TRUE;
      send_ack(sock,seq+1);
      return;
    }
    //收到syn
    if (flags & SYN_FLAG_MASK){
      sock->their_syn = TRUE;
      if(flags & ACK_FLAG_MASK){
        sock->window.last_ack_received = get_ack(pkt);
        send_ack(sock,seq+1);
      }
      return;
    }

    if (flags & ACK_FLAG_MASK){
        //printf("recv ack = %d last_ack_received = %d\n", get_ack(pkt),sock->window.last_ack_received);

        uint32_t advertised_window = get_advertised_window(pkt);
        edit_rwnd(sock,advertised_window);
        //收到冗余ACK
        if (get_ack(pkt) == sock->window.last_ack_received){
            update_cc_state(sock,DUPLICATE_ACK);        
        }
        //如果ack序号大于之前的，更新收到的ack序号
        if(get_ack(pkt) > sock->window.last_ack_received) {
            gettimeofday(&sock->recv_time,NULL);
            edit_timer(sock);
            sock->window.last_ack_received = get_ack(pkt);
            update_cc_state(sock,NEW_ACK);
        }
        //printf("receive ack is %d \n",get_ack(pkt) );
        return;
    }


    //printf("receive seq is %d, expected_rev_seq is %d\n",seq,sock->window.expected_rev_seq);
    //printf("datalen is %d \n",get_plen(pkt) - DEFAULT_HEADER_LEN);
    //如果达到的seq 和期望不一致，立即发送冗余ACK，指示下一个期待的字节序号
    if (seq != sock->window.expected_rev_seq && sock->window.expected_rev_seq > 0 ){
        //printf("recv seq = %d expected_rev_seq = %d\n", seq,sock->window.expected_rev_seq);
        send_ack(sock,sock->window.expected_rev_seq);
        return;
    }

    //如果收到新的包，并且新的包的序号等于下一个要接收的包的序号，将新的包内容放入缓冲区,发送ACK
    if(seq == sock->window.expected_rev_seq){
        data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
        sock->window.expected_rev_seq = seq + data_len; 
        //printf("datalen = %d seq = %d\n",data_len, seq);
        if(sock->received_buf == NULL){
            sock->received_buf = malloc(data_len);
        }
        else{
            sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len);
        }
        memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN, data_len);
        sock->received_len += data_len;

        send_ack(sock,seq+data_len);
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
    len = 0;
    len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
               (struct sockaddr *) &(sock->conn), &conn_len); 
    total_len = total_len + len;
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return total_len;
}

//发送数据
void send_datas(cmu_socket_t *sock, char *data, int buf_len, uint32_t seq_from){
  //puts("send_datas");
  char* msg;
  char* data_offset = data;
  int sockfd, plen;
  size_t conn_len = sizeof(sock->conn);
  uint32_t seq = seq_from;
  uint32_t adv_window = get_my_adv_window(sock);
  sockfd = sock->socket;

  if(buf_len > 0){
    while(buf_len != 0){
      if(buf_len <= MAX_DLEN){
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
void resend(cmu_socket_t * sock){
    //puts("re_send");
    if (sock->tmp_buf == NULL)
      return;
    sock->edit_time_flag = FALSE;
    uint32_t send_base = sock->window.last_ack_received;
    uint32_t min_window = get_min_window_size(sock);
    uint32_t have_sent_size = (sock->window.last_ack_received - sock->window.last_send_base);
    uint32_t send_size = sock->tmp_len - have_sent_size < min_window ? sock->tmp_len - have_sent_size : min_window;
    //printf("tmp_buf = %p send_size = %d \n", sock->tmp_buf,send_size);
    send_datas(sock,sock->tmp_buf+have_sent_size,send_size,send_base);
}
//开始发送数据
void begin_send(cmu_socket_t * sock){
    puts("begin_send");
    uint32_t min_window;
    sock->edit_time_flag = TRUE;
    while (TRUE){
        sock->window.last_send_base = sock->window.last_ack_received;
        min_window = get_min_window_size(sock);
        while(pthread_mutex_lock(&(sock->send_lock)) != 0);
        uint32_t buf_len = sock->sending_len;  
        if (sock->tmp_len < min_window && buf_len != 0){
            //printf("tmp_len = %d min_window = %d buf_len = %d last_send_base = %d\n", sock->tmp_len,min_window,buf_len,sock->window.last_send_base);
            sock->tmp_buf = realloc(sock->tmp_buf,min_window);
            uint32_t add_size = (min_window - sock->tmp_len) < buf_len ? (min_window - sock->tmp_len): buf_len;
            sock->tmp_len = sock->tmp_len + add_size;
            memcpy(sock->tmp_buf,sock->sending_buf,add_size);
            uint32_t left_size = buf_len - add_size;
            char * left_data = calloc(buf_len - add_size,1);
            memcpy(left_data,sock->sending_buf + add_size, buf_len - add_size);
            free(sock->sending_buf);
            sock->sending_buf = left_data;
            sock->sending_len = left_size;
        }
        pthread_mutex_unlock(&(sock->send_lock));
        if (sock->tmp_len <= 0){
          break;
        }
        gettimeofday(&sock->send_time,NULL);
        
        struct timeval time1;
        struct timeval time2;
        gettimeofday(&time1,NULL);
        send_datas(sock,sock->tmp_buf,sock->tmp_len,sock->window.last_ack_received);
        while (TRUE){
          check_for_data(sock, TIMEOUT);
          gettimeofday(&time2,NULL);
          if (sock->window.last_ack_received > sock->window.last_send_base)
            break;
          if (is_timeout(sock,&time1,&time2)){
              sock->edit_time_flag = FALSE;
 
              update_cc_state(sock,DELAY);
              break;
          }
        }
        int have_sent_size = (sock->window.last_ack_received - sock->window.last_send_base);
        sock->tmp_len = sock->tmp_len - have_sent_size;
        if (sock->tmp_len == 0)
          sock->edit_time_flag = TRUE;
        char * new_data = malloc(sock->tmp_len);
        memcpy(new_data,sock->tmp_buf + have_sent_size,sock->tmp_len);
        free(sock->tmp_buf);
        sock->tmp_buf = new_data;
    }
    free(sock->tmp_buf);
    sock->edit_time_flag = FALSE;
    sock->tmp_len = 0;
    sock->tmp_buf = NULL;
}
/*
 * Param: in - the socket that is used for backend processing
 *
 * Purpose: To poll in the background for sending and receiving data to
 *  the other side. 
 *
 */
void* begin_backend(void * in){

  cmu_socket_t * dst = (cmu_socket_t *) in;

  int death, buf_len, send_signal;
  char* data;

  while(TRUE){
    while(pthread_mutex_lock(&(dst->death_lock)) !=  0);
    death = dst->dying;
    pthread_mutex_unlock(&(dst->death_lock));
    
    
    while(pthread_mutex_lock(&(dst->send_lock)) != 0);
    buf_len = dst->sending_len;
    pthread_mutex_unlock(&(dst->send_lock));
    //printf("backend tmp_len = %d  rwnd = %d cwnd = %d buf_len = %d recv_len = %d ,mydying = %d their_fin = %d last_ack_received = %d \n", dst->tmp_len,get_rwnd(dst),get_cwnd(dst),buf_len,dst->recv,dst->my_fin,dst->their_fin,dst->window.last_ack_received);
    //如果自己的buf_len 等于0 并且接到对方的fin 且发的fin 被接到了，那么停下来等待一段时间
    if(death && buf_len == 0 && dst->their_fin  && dst->my_fin){
      puts("thread wait to exit");
      while (TRUE){
          //设置时间为2 * Maximum segment lifetime
          dst->timeout_interval.tv_sec = 10 * dst->timeout_interval.tv_sec;
          dst->timeout_interval.tv_usec = 10 * dst->timeout_interval.tv_usec;
          if (check_for_data_inner(dst,TIMEOUT) == 0)
            break;
      }

      
      break;
    }

    if(buf_len > 0){
      //printf("sending_buf = %d\n", dst->sending_len);
      begin_send(dst); 
      //pthread_mutex_unlock(&(dst->send_lock));
    }
    while(pthread_mutex_lock(&(dst->send_lock)) != 0);
    buf_len = dst->sending_len;
    pthread_mutex_unlock(&(dst->send_lock));

    if (buf_len == 0 && dst->tmp_len == 0 && dst->dying){
        pthread_cond_signal(&(dst->close_wait_cond)); 
    }
        

    check_for_data(dst, NO_WAIT);
    
    while(pthread_mutex_lock(&(dst->recv_lock)) != 0);
    
    if(dst->received_len > 0 || dst->their_fin)
      send_signal = TRUE;
    else
      send_signal = FALSE;
    pthread_mutex_unlock(&(dst->recv_lock));
    
    if(send_signal){
      pthread_cond_signal(&(dst->wait_cond));  
    }
  }


  pthread_exit(NULL); 
  return NULL; 
}

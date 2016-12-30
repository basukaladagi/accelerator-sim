#ifdef __cplusplus
#define DPI_LINKER_DECL  extern "C" 
#else
#define DPI_LINKER_DECL
#endif

#include "svdpi.h"
#include <stdio.h>
#include <string.h>    //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include <sys/types.h>  
#include <sys/socket.h> 
#include <sys/un.h> 
#include <sys/wait.h> 
#include <fcntl.h> 
#include <signal.h> 
#include <errno.h> 
#include "npu.h"

#define DTMP 4096

#define QEMU_DEFAULT_SOCK "/tmp/ivshmem_socket"

DPI_LINKER_DECL int C_init_socket();
DPI_LINKER_DECL int C_close_socket();
DPI_LINKER_DECL int C_req_read (int addr, int width, int len, volatile unsigned char *data);
DPI_LINKER_DECL int C_req_write(int addr, int width, int len, unsigned char *data);

DPI_LINKER_DECL int C_req_interrupt(int vector);
DPI_LINKER_DECL int C_master_loop();
DPI_LINKER_DECL int V_master_posedge();
DPI_LINKER_DECL int V_master_read (int addr, int len, unsigned char *data);
DPI_LINKER_DECL int V_master_write(int addr, int len, unsigned char *data);

int sock;
int client_sock = 0; // Client socket which should be used.
int client_init = 0; // Client is initialized
int send_ok = 0;  // set when C_req_read/C_req_write can be called.

struct sockaddr_un server;
char message[1000] , server_reply[2000];
char host_rdata[DTMP];
char host_wdata[DTMP];

void recv_from_qemu(int read_fd, NpuData *output)
{
        NpuData temp_npu;
        int nbytes;

	printf("in %s :sizeof npudata:%d\n", __func__, sizeof(NpuData));
        memset(&temp_npu, 0, sizeof(temp_npu));
        memset(output, 0, sizeof(NpuData));
        //printf("Reading from socjet:%d\n", read_fd);
        //nbytes = recv(read_fd, (char *)&temp_npu, sizeof(temp_npu), 0);
        nbytes = recv(read_fd, (char *)output, sizeof(NpuData), 0);
        if (nbytes < 0) {
                printf("Read error: %d\n", nbytes);
        }
        if (nbytes == 0) {
                //printf("End of file\n");
        } else {
                printf("++++++Data from QEMU+++++++\n");
                printf("bytes received: %d\n", nbytes);
                printf("received success\n");
               // printf("address: %p\n", temp_npu.address);
               // printf("size: %p\n", temp_npu.data_size);
               // printf("data: 0x%x\n", temp_npu.temp_data);
               // printf("operation: %lu\n", temp_npu.guest_op);
		printf("address: %p\n", output->address);
                printf("size: %p\n", output->data_size);
                printf("data: 0x%x\n", output->temp_data);
                printf("operation: %lu\n", output->guest_op);
                printf("++++++++++++++++++++++++++\n");
        }
}

void qemu_dma_write(int addr, int width, int len, unsigned char *data)
{
    int ret;
    char temp[100] = "\0";
    struct msghdr msg;
    struct iovec iov[1];
    NpuData npu;

    memset(&npu, 0, sizeof(NpuData));

    npu.magic = 47806;
    npu.flags = 2;  /* host to guest, make these enums */
    npu.data_size = sizeof(uint64_t); /* temporary, change it to len */
    //strncpy(&npu.data, "good stuff", 12);
    npu.address = addr;
    npu.host_req = 1;  // write
    npu.temp_data = 24;  // use data, testing right now

    iov[0].iov_base = &npu;
    iov[0].iov_len = sizeof(npu);

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    printf("Before calling sendmsg in %s\n", __func__);
    sleep(10);

    ret = sendmsg(client_sock, &msg, 0);
    if (ret <= 0) {
            printf("Failed to send in %s\n", __func__);
	    exit(1);
    }
    printf("%s: sendmsg success\n", __func__);
// Wait till the write goes through, else it will be recursive.
    sleep(30);
}

void hexdmp(char *buf, int n)
{
	int i =0;
	if(buf) {
    		printf("-------- HEXDUMP-------------");
		for (i = 0; i < n; i++)
		{
			printf("%02X", buf[i]);
		}
	}
}

//new API:void qemu_msi_interrupt(int vector)
void qemu_msi_interrupt(int vector, int data)
{
    int ret;
    char temp[100] = "\0";
    struct msghdr msg;
    struct iovec iov[1];
    NpuData npu;

    memset(&npu, 0, sizeof(NpuData));

    npu.magic = 47806;
    npu.flags = 2;  /* host to guest, make these enums */
    npu.data_size = sizeof(uint64_t); /* temporary, change it to len */
    //strncpy(&npu.data, "good stuff", 12);
    npu.host_req = 3;  // INDICATES INTERRUPT.
    npu.temp_data = data;  // use data, testing right now
    npu.vector = 0;  // Default vector is zero as of now.

    iov[0].iov_base = &npu;
    iov[0].iov_len = sizeof(npu);

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    sleep(10);

    ret = sendmsg(client_sock, &msg, 0);
    if (ret <= 0) {
            printf("Failed to send in %s\n", __func__);
	    exit(1);
    }
    printf("%s: sendmsg success\n", __func__);
// Wait till the write goes through, else it will be recursive.
    sleep(30);
}

void qemu_dma_read(int addr, int width, int len, volatile unsigned char *data){
    int ret;
    char temp[100] = "\0";
    struct msghdr msg;
    struct iovec iov[1];
    NpuData npu;
    NpuData data_frm_qemu;
    int indx = 0;

    int buf_len =  (len + 1) * width;  // assuming buf_len < 4K, else create multiple iov

    printf("in %s :sizeof npudata:%d\n", __func__, sizeof(NpuData));
    printf("Len :%d\n", len);
    printf("buf_len:%d\n", buf_len);

    memset(&npu, 0, sizeof(NpuData));
    memset(&data_frm_qemu, 0, sizeof(NpuData));


    npu.magic = 47806;
    npu.flags = 2;  /* host to guest, make these enums */
//    npu.data_size = sizeof(uint64_t); /* temporary, change it to len */
    npu.data_size = buf_len;
    //strncpy(&npu.data, "good stuff", 12);
    npu.address = addr;
    npu.host_req = 2;  // read
    //npu.temp_data = 24;  // use data

    iov[0].iov_base = &npu;
    iov[0].iov_len = sizeof(npu);

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    printf("before sleepinggg and sendmsg\n");
// Wait till QEMU boots up.
    sleep(10);

    ret = sendmsg(client_sock, &msg, 0);
    if (ret <= 0) {
            printf("Failed to send in %s\n", __func__);
        return -1;
    }else {
	printf("Send successfull\n");
    }
    printf("before recv_from_qemu:%d\n", __LINE__);
    sleep(10);
    recv_from_qemu(client_sock, &data_frm_qemu);
    printf("in %s : ====data_frm_qemu======\n", __func__);
    printf("data_frm_qemu.data_size: %d\n", data_frm_qemu.data_size);
    for(indx = 0; indx < data_frm_qemu.data_size; indx++) {
    	printf("%x", data_frm_qemu.data_test[indx]);
    }
    memcpy(data, data_frm_qemu.data_test, indx);
    printf("\nDOne here:%s\n", __func__);
}
//int
//send_to_qemu(void *cop, int sock)
int
send_to_qemu(int sock, NpuData *input)
{
    int ret;
    char temp[100] = "\0";
    struct msghdr msg;
    struct iovec iov[1];
    NpuData npu;

    memset(&npu, 0, sizeof(NpuData));


    npu.magic = 47806;
    npu.flags = 2;  /* host to guest, make these enums */
    npu.data_size = sizeof(uint64_t); /* temporary */
    //strncpy(&npu.data, "good stuff", 12);
    npu.address = 0x1234;
    npu.host_req = 1;
    npu.temp_data = 24;
#if 0
    npu.address = cop->address;
    if(cop->ops == 1) {
        npu.host_req = 1;
        npu.temp_data = cop->temp_data;
    } else if(cop->ops == 2) {
        npu.host_req = 2;
    }
    printf(" address: %p\n", npu.address);
    printf(" temp_data: %ld\n", npu.temp_data);
#endif

    //iov[0].iov_base = &npu;
    //iov[0].iov_len = sizeof(npu);

    iov[0].iov_base = input;
    iov[0].iov_len = sizeof(NpuData);
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    ret = sendmsg(sock, &msg, 0);
    if (ret <= 0) {
            printf("Failed to send in %s\n", __func__);
        return -1;
    }
    printf("scucess :in send_clientData\n");

    return 0;
}


void sig_han(void)
{
//    int saved_errno = errno;
    printf("In signal handler\n");

    while(waitpid(-1, NULL, WNOHANG) > 0);

  //  errno = saved_errno;
}

int C_master_loop()
{
    int i, j, len;
    struct sigaction sa;
    len = 0;
    fd_set fds, orig_fds;
    int max_fd;
    int ret = 0;
    struct sockaddr_un newaddr;
    socklen_t newaddr_len = 0;
    int client_fd = 0;
    struct timeval waitd = {0, 0};

    sa.sa_handler = sig_han;
    sa.sa_flags = 0;

    sigemptyset(&sa.sa_mask);

    if(sigaction(SIGCHLD, &sa, NULL) == -1) {
	perror("Failed to ignore sigchild");
    }

    for ( i=0; i<DTMP; ++i )
        host_wdata[i] = i & 0xFF;

    for ( i=0; i<10; i++ )
        V_master_posedge();

    // get address + len from qemu and filter first 32 bytes.

    FD_ZERO(&orig_fds);
    FD_SET(sock, &orig_fds);

    max_fd = sock + 1;

    printf("Starting loop\n");

    while(1) {
	FD_ZERO(&fds);
	memcpy(&fds, &orig_fds, sizeof(orig_fds));
        ret = select(max_fd + 1, &fds, NULL, NULL, &waitd);
	if (ret < 0) {
		if(errno == EINTR) {
    //    	   V_master_posedge();
		   continue;
		}
		break;
	}
	if (ret == 0) {
		if((client_fd > 0) && (client_init == 1)) {
			send_ok = 1;
			//printf("Sleepingggg\n");
// TODO: enable
        	   	V_master_posedge();
//			sleep(5);
		}
		continue;
	}
	if (FD_ISSET(sock, &fds)) {
			send_ok = 0;
		// accept new connection.
		puts("New connection");
                client_fd = accept(sock, &newaddr, &newaddr_len);
		client_sock = client_fd;
		client_init = 1;
		fcntl(client_fd, F_SETFL, O_NONBLOCK);
		FD_SET(client_fd, &orig_fds);
		if(client_fd > max_fd) {
			max_fd = client_fd + 1;
		}
// TODO: enable
   	   V_master_posedge();
	}
	if (FD_ISSET(client_fd, &fds)) {
		NpuData data_frm_qemu;
		memset(&data_frm_qemu, 0, sizeof(NpuData));
		send_ok = 0;
//		printf("Actual info from qemu\n");
		recv_from_qemu(client_fd, &data_frm_qemu);
//		printf("Sending to qemu\n");
//		(void)send_to_qemu(client_fd);
// TODO: Enable this to test C_req_read/C_req_write
        	   V_master_posedge();

		if(data_frm_qemu.guest_op == 2) {
			printf("Read operation on QEMU\n");
			//Read operation happened on QEMU.
			int newlen = 0;
			int newremainder= 0;
			uint8_t dummy[8];
			int z = 0;
			NpuData data_to_qemu;
			memset(&data_to_qemu, 0, sizeof(NpuData));
			printf("Read addr:0x%x, len:%d\n",
				data_frm_qemu.address,
				data_frm_qemu.data_size);
			if(data_frm_qemu.data_size <= 32) {
				newlen =  0;
			} else {
				newlen = data_frm_qemu.data_size/32;
				newremainder = data_frm_qemu.data_size  % 32;
				if(newremainder == 0) {
					newlen = newlen - 1;
				}
				
			}
				
   		    V_master_read(data_frm_qemu.address, newlen, dummy);
   		    //V_master_read( 0xD1234567, len, host_rdata );
			printf("After reading from HDL");
			for(z=0; z< 8; z++) {
				printf("%x",dummy[z]);
			}
			printf("\n");
			V_master_posedge();
		      data_to_qemu.magic = 47806;
		      data_to_qemu.address = data_frm_qemu.address;
		      data_to_qemu.data_size= data_frm_qemu.data_size;
		      //data_to_qemu.temp_data= 0xaa; //testing
		      data_to_qemu.temp_data= dummy[0]; //testing
			printf("Actual data read:0x%x\n", data_to_qemu.temp_data); 
		      data_to_qemu.flags =  2; //host->guest
		      data_to_qemu.host_req=  0; //noop 
		      (void)send_to_qemu(client_fd, &data_to_qemu);
		}
		if(data_frm_qemu.guest_op == 1) {
			int newlen = 0;
			int newremainder= 0;
			//Write operation happened on QEMU.
			printf("Write operation on QEMU\n");
			NpuData data_to_qemu;
			memset(&data_to_qemu, 0, sizeof(NpuData));
			printf("Write addr:0x%x, len:%d\n",
				data_frm_qemu.address,
				data_frm_qemu.data_size);
                	printf("data: 0x%x\n", data_frm_qemu.temp_data);
			sprintf(data_frm_qemu.data_test,"%d", data_frm_qemu.temp_data); 
			if(data_frm_qemu.data_size <= 32) {
				newlen =  0;
			} else {
				newlen = data_frm_qemu.data_size/32;
				newremainder = data_frm_qemu.data_size  % 32;
				if(newremainder == 0) {
					newlen = newlen - 1;
				}
				
			}
                        V_master_write(data_frm_qemu.address, 
					newlen,
				       data_frm_qemu.data_test);
			V_master_posedge();
		}

	}
//TODO: enable this
        	   V_master_posedge();
    }

    V_master_read( 0xD1234567, len, host_rdata );

    for ( i=0; i<32*(len+1); i=i+8 ) {
        printf( "DPI-C: C_master_loop: read : RDATA[%3d:%3d]=0x", (i+8)*8-1, i*8 );
        for ( j=7; j>=0; j-- ) {
            printf( "%02x", (unsigned char)host_rdata[i+j] );
        }
        printf( "\n" );
    }

    for ( i=0; i<10; i++ )
        V_master_posedge();

    V_master_write( 0xD0D0D0D0, len, host_wdata );
}

int C_close_socket()
{
    puts("Socket closed");
    close(sock);
    return 0;
}

int C_init_socket()
{

    int ret = 0; 
    //Create socket
    sock = socket(AF_UNIX, SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
     
    server.sun_family = AF_UNIX;
    ret = snprintf(server.sun_path, sizeof(server.sun_path),"%s",
	     QEMU_DEFAULT_SOCK);
    //server.sin_addr.s_addr = inet_addr("127.0.0.1");
    //server.sin_family = AF_INET;
    //server.sin_port = htons( 8888 );

    ret = bind(sock, (struct sockaddr *) &server, sizeof(server));
    if(ret < 0) {
	printf("Bind failed :%d\n", ret);
	//puts(perror("bind"));
    } 
    if(listen(sock, 10) < 0) {
	puts("listen fails");
    }
    printf("Listening\n");
    //C_master_loop();

    //Connect to remote server
#if 0
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }
     
    puts("Connected\n");
#endif
    return 0;    
}

// width is always 32 byte
// len : how many 32 byte read's
// try with 0
int C_req_read(int addr, int width, int len, volatile unsigned char *data)
{
    int i;
    printf( "C: HDL ->QEMU: Read : RADDR=0x%x, WIDTH=%u, LEN=%u\n", addr, width, len);

    printf("Before exiting in C_req_read\n");
    //exit(1);
#if 0
    message[0] = 'h';
    message[1] = 'e';
    message[2] = 'l';
    message[3] = 'l';
    message[4] = 'o';
    message[5] = '\0';
#endif
     
    // send back read data to HDL
    for ( i=0; i<DTMP; ++i )
        data[i] = addr & 0xFF;
    //    data[i] = i & 0xFF;

    //Send some data
    //while (send_ok != 1);
    if(send_ok == 1) {
	    printf("Before doing qemu_dma_read\n");
    	    width =  32 ; //Current default
	    qemu_dma_read(addr, width, len, data);
#if 0
	    if( send(sock , message , strlen(message) , 0) < 0)
	    {
		    puts("Send failed");
		    return 1;
	    }

	    //Receive a reply from the server
	    if( recv(sock , server_reply , 2000 , 0) < 0)
	    {
		    puts("recv failed");
		    //break;
	    }

	    puts("Server reply :");
	    puts(server_reply);
#endif
    } else {
		printf("QEMU not yet initialized\n");	
    }

    return 0xDEADBEEF;
}

int C_req_interrupt(int vector)
{
    int i, j;
    printf( "C: HDL ->QEMU: interrupt vector: %d\n", vector);
    //while (send_ok != 1);
    if(send_ok == 1){
	qemu_msi_interrupt(0,0);
    }
    return 0;
}

int C_req_write(int addr, int width, int len, unsigned char *data)
{
    int i, j;
    printf( "C: HDL ->QEMU: Write: WADDR=0x%x, WIDTH=%u, LEN=%u\n", addr, width, len);
    //while (send_ok != 1);
    if(send_ok == 1){
	printf("Calling qemu_dma_write\n");
    	width =  32 ; //Current default
	qemu_dma_write(addr, width, len, data);
	//qemu_msi_interrupt(0,0);
    }
#if 0
	   for ( i=0; i<32*(len+1); i=i+8 ) {
        printf( "C: HDL ->QEMU: Write: WDATA[%3d:%3d]=0x", (i+8)*8-1, i*8 );
        for ( j=7; j>=0; j-- ) {
            printf( "%02x", data[i+j] );
        }
        printf( "\n" );
    }
#endif
    return 0xABADCAFE;
}

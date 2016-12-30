
#define HOST_CLIENT_SOCKET_PATH "/tmp/host_client_socket"
#define MAX_DATA 4086 /* 4K bytes to be sent/received */

typedef enum NpuOperations{
	GUEST_TO_HOST = 1,	/* Msg comes from guest to host */
	HOST_TO_GUEST = 2	/* Msg is sent from host to guest */
} NpuOperations;

int qemu_write(uint64_t addr, char * buf, uint64_t size);
int qemu_read(uint64_t addr, char * buf, uint64_t size);

typedef struct ClientOp {
	uint32_t ops;  /* 1: write, 2: read */
	uint64_t address; /* address on which op should be done */
	uint64_t temp_data;
	uint64_t data_size;
	char data[MAX_DATA];
} ClientOp;

typedef struct NpuData {
	/* TODO: check if you need NpuOperations */
	uint32_t magic;		/* hex value : 47806 */
	uint32_t flags;	/* 1: guest->host, 2: host-> guest */
	uint32_t data_size;
	uint32_t host_req;   /* request from host to guest, 1: write, 2: read */
	uint32_t guest_op;  /* 1: write, 2: read, operation that happened on guest */
	uint64_t address; /* address on which operation was made or shd be made */
	uint64_t temp_data; /* testing */
//	char data[MAX_DATA];
	uint32_t vector;  /* used in case of sending interrupt */
	uint8_t data_test[MAX_DATA];
} NpuData;

void qemu_dma_read(int addr, int width, int len, volatile unsigned char *data);
void qemu_dma_write(int addr, int width, int len, unsigned char *data);
void recv_from_qemu(int read_fd, NpuData *output);
int send_to_qemu(int sock, NpuData *input);

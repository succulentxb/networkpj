TOP_DIR = .
INC_DIR = $(TOP_DIR)/inc
SRC_DIR = $(TOP_DIR)/src
BUILD_DIR = $(TOP_DIR)/build
TEST_DIR = $(TOP_DIR)/test

CC=gcc
FLAGS = -pthread -g -ggdb -Wall -DDEBUG -I$(INC_DIR)
OBJS = $(BUILD_DIR)/cmu_packet.o \
	$(BUILD_DIR)/cmu_tcp.o \
	$(BUILD_DIR)/backend.o \


default:all
all: server client bic_server bic_client

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | build_dir
	$(CC) $(FLAGS) -c -o $@ $<

server: $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/server.c -o server $(OBJS)

client: $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/client.c -o client $(OBJS)


bic_server: $(BUILD_DIR)/bic_tcp.o $(BUILD_DIR)/cmu_tcp.o $(BUILD_DIR)/cmu_packet.o
	$(CC) $(FLAGS) $(SRC_DIR)/server.c -o bic_server $(BUILD_DIR)/bic_tcp.o $(BUILD_DIR)/cmu_tcp.o $(BUILD_DIR)/cmu_packet.o
bic_client: $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/client.c -o bic_client $(BUILD_DIR)/bic_tcp.o $(BUILD_DIR)/cmu_tcp.o $(BUILD_DIR)/cmu_packet.o

build_dir:
	mkdir -p $(BUILD_DIR)

# run tests
test: all testing_server
	head -c 100M </dev/urandom > $(TEST_DIR)/random.input
	sudo python2 -m pytest -vs -p no:warnings $(TEST_DIR)

testing_server: $(OBJS)
	$(CC) $(FLAGS) $(TEST_DIR)/testing_server.c -o $(TEST_DIR)/testing_server $(OBJS)

clean:
	-rm -f $(BUILD_DIR)/*.o client server testing_server bic_server bic_client $(TEST_DIR)/file.c $(TEST_DIR)/random.input $(TEST_DIR)/f1.txt

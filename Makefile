CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -Iinclude -Wno-deprecated-declarations
LDFLAGS = -lpcap -lssl -lcrypto -lpthread

SRC_DIR = src
OBJ_DIR = src
BIN = crock

OBJS = $(OBJ_DIR)/main.o $(OBJ_DIR)/Crock.o

all: $(BIN)

$(BIN): $(OBJS)
	$(CXX) $(OBJS) -o $(BIN) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ_DIR)/*.o $(BIN)

.PHONY: all clean

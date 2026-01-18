CXX = g++
CXXFLAGS = -O3 -std=c++17
LDFLAGS = -lsqlite3 -lpthread -ltorrent-rasterbar
TARGET = dht_db
SRC = dht_db.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean


TOOLS_SRC := tools
TOOLS_BIN := $(patsubst $(TOOLS_SRC)/%.cpp, %, $(wildcard $(TOOLS_SRC)/*.cpp))
COMMON_SRC := common
COMMON_OBJ := $(patsubst %.cpp, %.o, $(wildcard $(COMMON_SRC)/*.cpp))

PREFIX ?= /usr/local
INSTALL ?= install
RM ?= rm
CXXFLAGS += -w

all: $(TOOLS_BIN)

%.o: %.cpp
	@echo compiling $< ...
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(TOOLS_BIN): %: $(TOOLS_SRC)/%.o $(COMMON_OBJ)
	@echo linking $@ ...
	@$(CXX) $(CXXFLAGS) -o $@ $< $(COMMON_OBJ)

clean:
	@$(RM) -fv $(TOOLS_BIN) $(TOOLS_SRC)/*.o $(COMMON_OBJ)

install: all
	@$(INSTALL) --verbose --strip --mode=4755 --owner=root $(TOOLS_BIN) $(PREFIX)/bin
	
uninstall:
	@for file in $(TOOLS_BIN); do $(RM) -v $(PREFIX)/bin/$$file; done

.PHONY: all clean install uninstall

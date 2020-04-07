CC = $(CROSS_COMPILE)gcc
CFLAGS += -Os -g -Werror -Wall

all: clean testhelperd

testhelperd:
	$(CC) $(CFLAGS) testhelperd.c -o testhelperd
clean:
	rm -rf testhelperd __log.*

IP ?= 127.0.0.1
PORT ?= 1234
test:
	./testhelperd -p $(PORT) -t 1 -d -v
	./testhelper.py -v $(IP):$(PORT) shellcmd ls "ls -al"
	./testhelper.py -v $(IP):$(PORT) shellcmd "tail -f README.md"
	./testhelper.py -v $(IP):$(PORT) putfile /etc/hosts hosts
	diff hosts /etc/hosts
	./testhelper.py -v $(IP):$(PORT) getfile /etc/hosts hosts
	diff hosts /etc/hosts
	./testhelper.py -v $(IP):$(PORT) quitexe



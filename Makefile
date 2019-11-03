testhelperd:
	gcc testhelperd.c -g -Werror -Wall -o testhelperd

test:
	./testhelperd -p 1234 -d
	./testhelper.py 192.168.0.23:1234 shellcmd ls "ls -al"
	./testhelper.py 192.168.0.23:1234 quitexe

all:
	make testhelperd
	make test
	rm testhelperd

testhelperd:
	gcc testhelperd.c -g -Werror -Wall -o testhelperd

test:
	./testhelperd -p 1234 -t 5 -d -v
	./testhelper.py 192.168.0.23:1234 shellcmd ls "ls -al"
	./testhelper.py 192.168.0.23:1234 shellcmd "tail -f README.md"
	./testhelper.py 192.168.0.23:1234 putfile /etc/hosts hosts
	./testhelper.py 192.168.0.23:1234 quitexe

all:
	make testhelperd
	make test
	rm testhelperd

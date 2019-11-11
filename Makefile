testhelperd:
	gcc testhelperd.c -g -Werror -Wall -o testhelperd

test:
	./testhelperd -p 1234 -t 5 -d -v
	./testhelper.py -v 192.168.0.23:1234 shellcmd ls "ls -al"
	./testhelper.py -v 192.168.0.23:1234 shellcmd "tail -f README.md"
	./testhelper.py -v 192.168.0.23:1234 putfile /etc/hosts hosts
	./testhelper.py -v 192.168.0.23:1234 quitexe

clean:
	rm -rf testhelperd __log.*

all:
	make testhelperd
	make test

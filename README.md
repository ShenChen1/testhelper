# Linux test helper
Run cmd on target machine via testhelperd

## Compile
```
[root@sc testhelper]# gcc testhelperd.c -g -Werror -Wall -o testhelperd
```

## Server
```
[root@sc testhelper]# ./testhelperd -p 1234 -d
```

## Client
```
[root@sc testhelper]# ./testhelper.py 192.168.0.23:1234 shellcmd ls "ls -al"
PID[13704]-[INFO]: Running 'ls' ... 
hosts
Makefile
README.md
testhelperd
testhelperd.c
testhelper.py

PID[13704]-[INFO]: Running 'ls -al' ... 
total 80
drwxr-xr-x 2 root root   125 Nov 12 21:51 .
drwxr-xr-x 5 root root    53 Nov 12 21:17 ..
-rw-r--r-- 1 root root    42 Nov 12 21:18 .git
-rw-r--r-- 1 root root   520 Nov 12 21:40 Makefile
-rw-r--r-- 1 root root   318 Nov 12 21:50 README.md
-rwxr-xr-x 1 root root 33648 Nov 12 21:50 testhelperd
-rw-r--r-- 1 root root 19973 Nov 12 21:40 testhelperd.c
-rwxr-xr-x 1 root root  9906 Nov 12 21:40 testhelper.py

[root@sc testhelper]# ./testhelper.py 192.168.0.23:1234 putfile /etc/hosts hosts
PID[13711]-[INFO]: Begin to send '/etc/hosts' ... 
PID[13711]-[INFO]: Sending '/etc/hosts' ... (100.00 %)

[root@sc testhelper]# ./testhelper.py 192.168.0.23:1234 getfile /etc/hosts hosts
PID[13714]-[INFO]: Begin to receive '/etc/hosts' ... 
PID[13714]-[INFO]: Receiving '/etc/hosts' ... (100.00 %)

```


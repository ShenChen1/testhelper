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
PID[8492]-[INFO]: Running 'ls' ... 
README.md
testhelperd.c
testhelper.py

PID[8492]-[INFO]: Running 'ls -al' ... 
total 32
drwxr-xr-x 2 root root    77 Nov  4 04:20 .
drwxr-xr-x 5 sc   root    53 Nov  3 04:43 ..
-rw-r--r-- 1 root root    42 Nov  3 04:43 .git
-rw-r--r-- 1 root root   241 Nov  4 04:20 README.md
-rw-r--r-- 1 root root 13593 Nov  4 03:35 testhelperd.c
-rwxr-xr-x 1 root root  4409 Nov  4 04:18 testhelper.py

```


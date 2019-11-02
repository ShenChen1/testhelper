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
[root@sc testhelper]# ./testhelper.py 192.168.0.23:1234 shellcmd "ls" "ls -al"
README.md
testhelperd
testhelperd.c
testhelper.py

total 61
drwxrwxrwx 1 root root  4096 Nov  2 23:20 .
drwxrwxrwx 1 root root  4096 Nov  2 23:12 ..
drwxrwxrwx 1 root root  4096 Nov  2 23:19 .git
-rwxrwxrwx 1 root root   120 Nov  2 23:18 README.md
-rwxrwxrwx 1 root root 26848 Nov  2 23:20 testhelperd
-rwxrwxrwx 1 root root 12691 Nov  2 22:39 testhelperd.c
-rwxrwxrwx 1 root root  3929 Nov  2 23:10 testhelper.py

```


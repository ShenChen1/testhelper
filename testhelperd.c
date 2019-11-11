#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#define PROGNAME    "testhelperd"
#define VERSION     "0.003"

/*
protocol:

in:
(session) {command} base64-buf

out:
(session) <status> {command} base64-buf
*/

typedef struct {
    int     session;
    int     command;

    size_t  len;
    char   *buf;
} s_protocol_in;

typedef struct {
    int     session;
    int     status;
    int     command;

    size_t  len;
    char   *buf;
} s_protocol_out;

extern char *optarg;
extern int errno;

static char g_logfile[NAME_MAX];

static int g_verbose = 0;
static int g_daemonize = 0;
static int g_portno = 1314;
static int g_sockfd = 0;
static int g_session = 0;
static int g_pid = 0;
static int g_timeout = 30;

static FILE *g_ifp = 0;
static FILE *g_ofp = 0;
static FILE *g_lfp = 0;

typedef enum {
    CMD_TYPE_UNKNOWN,
    CMD_TYPE_HANDSHAKE,
    CMD_TYPE_TIMEOUT,

    CMD_TYPE_SHELLCMD,
    CMD_TYPE_PUTFILE,
    CMD_TYPE_GETFILE,
    CMD_TYPE_VERSION,
    CMD_TYPE_QUITEXE,

    CMD_TYPE_MAX
} e_cmd_type;

static const char *g_cmd_type[CMD_TYPE_MAX] = {
    [CMD_TYPE_UNKNOWN] = "unknown",
    [CMD_TYPE_HANDSHAKE] ="handshake",
    [CMD_TYPE_TIMEOUT] = "timeout",

    [CMD_TYPE_SHELLCMD] = "shellcmd",
    [CMD_TYPE_PUTFILE] = "putfile",
    [CMD_TYPE_GETFILE] = "getfile",
    [CMD_TYPE_VERSION] = "version",
    [CMD_TYPE_QUITEXE] = "quitexe",
};

static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
unsigned char * base64_encode(const unsigned char *src, size_t len,
                              size_t *out_len)
{
    unsigned char *out, *pos;
    const unsigned char *end, *in;
    size_t olen;
    int line_len;

    olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
    olen++; /* nul termination */
    if (olen < len)
        return NULL; /* integer overflow */
    out = malloc(olen);
    if (out == NULL)
        return NULL;

    end = src + len;
    in = src;
    pos = out;
    line_len = 0;
    while (end - in >= 3) {
        *pos++ = base64_table[in[0] >> 2];
        *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_table[in[2] & 0x3f];
        in += 3;
        line_len += 4;
    }

    if (end - in) {
        *pos++ = base64_table[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = base64_table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        } else {
            *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = base64_table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
        line_len += 4;
    }

    *pos = '\0';
    if (out_len)
        *out_len = pos - out;
    return out;
}

/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char * base64_decode(const unsigned char *src, size_t len,
                              size_t *out_len)
{
    unsigned char dtable[256], *out, *pos, block[4], tmp;
    size_t i, count, olen;
    int pad = 0;

    memset(dtable, 0x80, 256);
    for (i = 0; i < sizeof(base64_table) - 1; i++)
        dtable[base64_table[i]] = (unsigned char) i;
    dtable['='] = 0;

    count = 0;
    for (i = 0; i < len; i++) {
        if (dtable[src[i]] != 0x80)
            count++;
    }

    if (count == 0 || count % 4)
        return NULL;

    olen = count / 4 * 3;
    pos = out = malloc(olen);
    if (out == NULL)
        return NULL;

    count = 0;
    for (i = 0; i < len; i++) {
        tmp = dtable[src[i]];
        if (tmp == 0x80)
            continue;

        if (src[i] == '=')
            pad++;
        block[count] = tmp;
        count++;
        if (count == 4) {
            *pos++ = (block[0] << 2) | (block[1] >> 4);
            *pos++ = (block[1] << 4) | (block[2] >> 2);
            *pos++ = (block[2] << 6) | block[3];
            count = 0;
            if (pad) {
                if (pad == 1)
                    pos--;
                else if (pad == 2)
                    pos -= 2;
                else {
                    /* Invalid padding */
                    free(out);
                    return NULL;
                }
                break;
            }
        }
    }

    *out_len = pos - out;
    return out;
}

static void usage()
{
    fprintf(stderr,"usage: %s [-vd] [-t timeout] [-p port] [-w working directory]\n", PROGNAME);
    exit(EINVAL);
}

static int parse_config(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "vdt:p:w:")) != -1) {
        switch (opt) {
        case 'v':
            g_verbose = 1;
            break;
        case 'd':
            g_daemonize = 1;
            break;
        case 't':
            g_timeout = atoi(optarg);
            break;
        case 'p':
            g_portno = atoi(optarg);
            break;
        case 'w':
            chdir(optarg);
            break;
        default: /* '?' */
            usage();
        }
    }

    return 0;
}

static int do_daemon()
{
    if (g_daemonize) {
        if (daemon(1,1) != 0) {
            perror("daemon");
            exit(errno);
        }
    }

    /* Save pid */
    g_pid = getpid();

    return 0;
}

static int do_verbose()
{
    snprintf(g_logfile, sizeof(g_logfile),
             g_verbose ? "__log.%d" : "/dev/null", g_session);

    g_lfp = fopen(g_logfile, "w");
    if (!g_lfp) {
        perror("fdopen");
        exit(errno);
    }

    return 0;
}

static int __cleanup(int code)
{
    if (code == 0 && g_logfile == 0) {
        unlink(g_logfile);
    }

    exit(code);
}

static int __send_message(FILE *fp, char *fmt,...)
{
    va_list va;

    va_start(va, fmt);
    vfprintf(fp, fmt, va);
    va_end(va);

    fflush(fp);

    return 0;
}

static int send_reply(s_protocol_out *out)
{
    size_t outlen = 0;
    unsigned char *outstr = base64_encode((void *)out->buf, out->len + 1, &outlen);
    if (outstr == NULL) {
        return -ENOMEM;
    }

    __send_message(g_ofp, "(%d) <%d> {%s} %s\n",
                   g_session,
                   out->status,
                   g_cmd_type[out->command],
                   outstr);

    free(outstr);

    /* Debug */
    __send_message(g_lfp, "server: (%d) <%d> {%s} %s\n",
                   g_session,
                   out->status,
                   g_cmd_type[out->command],
                   out->buf);

    return 0;
}

static void __timeout(int sig)
{
    s_protocol_out out;

    /* kill the whole process group */
    kill(-getpid(), SIGTERM);

    memset(&out, 0, sizeof(s_protocol_out));
    out.session = g_session;
    out.status = ETIME;
    out.command = CMD_TYPE_TIMEOUT;
    out.buf = strerror(out.status);
    out.len = strlen(out.buf);
    send_reply(&out);

    __cleanup(0);
}

static int __parse_message(char *line, s_protocol_in *in)
{
    int i;
    char *buf = line;
    char *session = NULL;
    char *command = NULL;

    session = strchr(buf, '(') + 1;
    buf = strchr(buf, ')');
    if (buf == NULL) {
        goto err;
    }
    *buf++ = '\0';
    /* session */
    in->session = strtoul(session, NULL, 0);

    command = strchr(buf, '{') + 1;
    buf = strchr(buf, '}');
    if (buf == NULL) {
        goto err;
    }
    *buf++ = '\0';
    /* Find cmd type */
    for (i = 0; i < CMD_TYPE_MAX; i++) {
        if (!strcmp(g_cmd_type[i], command)) {
            in->command = i;
            break;
        }
    }
    if (i == CMD_TYPE_MAX) {
        goto err;
    }

    /* buf and len */
    buf = strchr(buf, ' ') + 1;
    if (buf == NULL) {
        goto err;
    }

    in->len = strlen(buf);
    in->buf = buf;

    return 0;

err:
    return -EINVAL;
}

static int do_shellcmd(char *line)
{
    int ret = 0;
    const char open_mode[] = "re";
    s_protocol_out out;

    /* Set process group, so that child can be killed by parent */
    setpgid(0, 0);

    FILE *popen_stream = popen(line, open_mode);
    if (popen_stream == NULL) {
        goto end;
    }

    int rs_size = 0;
    char *rs_buf = NULL;
    /* Get all output */
    while (1) {
        char *line = NULL;
        size_t len = 0;
        ssize_t read = getline(&line, &len, popen_stream);
        if (read == -1) {
            if (line) free(line);
            break;
        }

        rs_buf = realloc(rs_buf, rs_size + read + 1);
        rs_buf[rs_size + read] = '\0';
        strncpy(&rs_buf[rs_size], line, read + 1);
        rs_size += read;

        free(line);
    }

    int rc = pclose(popen_stream);
    if (rc == -1) {
        ret = -errno;
    } else if (WIFSIGNALED(rc)) {
        ret = -EINTR;
    } else if (WIFEXITED(rc)) {
        ret = WEXITSTATUS(rc);
    } else {
        ret = -EIO;
    }

end:
    memset(&out, 0, sizeof(s_protocol_out));
    out.session = g_session;
    out.status = -ret;
    out.command = CMD_TYPE_SHELLCMD;
    out.buf = rs_buf ? rs_buf : strerror(out.status);
    out.len = strlen(out.buf);
    send_reply(&out);

    /* Free the buffer for saving result */
    if (rs_buf) free(rs_buf);

    return ret;
}

static int do_putfile(char *line)
{
    /* srdfile dstfile length */
    int ret;
    FILE *fp = NULL;
    s_protocol_in in;
    s_protocol_out out;
    size_t length = 0;
    char srcfile[NAME_MAX];
    char dstfile[NAME_MAX];

    ret = sscanf(line, "%s %s %lu", srcfile, dstfile, &length);
    if (ret == EOF) {
        ret = -errno;
        goto end; 
    }

    /* Reply to client and let it send data */
    memset(&out, 0, sizeof(s_protocol_out));
    out.session = g_session;
    out.status = 0;
    out.command = CMD_TYPE_PUTFILE;
    out.buf = strerror(out.status);
    out.len = strlen(out.buf);
    send_reply(&out);

    /* Save file */
    fp = fopen(dstfile, "wb+");
    if (fp == NULL) {
        ret = -errno;
        goto end; 
    }

    size_t bytes = 0;
    while (length > bytes) {

        /* Read file data */
        char * line = NULL;
        size_t linelen = 0;
        ssize_t n = getline(&line, &linelen, g_ifp);
        if (n < 0) {
            if (line) free(line);
            /* Client disconnect */
            __cleanup(0);
        }

        ret = __parse_message(line, &in);
        if (ret && 
            in.session != g_session &&
            in.command != CMD_TYPE_PUTFILE) {
            ret = -EINVAL;
            goto end;
        }

        size_t bsize = 0;
        unsigned char *outstr = base64_decode((void *)in.buf, in.len + 1, &bsize);
        if (outstr == NULL) {
            ret = -ENOMEM;
            goto end;
        }

        /* Write */
        if (fwrite(outstr, 1, bsize, fp) != bsize) {
            ret = -ENODATA;
            goto end;
        }

        /* End once loop */
        free(outstr);
        bytes += bsize;

        /* ACK */
        memset(&out, 0, sizeof(s_protocol_out));
        out.session = g_session;
        out.status = 0;
        out.command = CMD_TYPE_PUTFILE;
        out.buf = strerror(out.status);
        out.len = strlen(out.buf);
        send_reply(&out);
    }

    /* End */
    fclose(fp);

    return 0;

end:
    memset(&out, 0, sizeof(s_protocol_out));
    out.session = g_session;
    out.status = -ret;
    out.command = CMD_TYPE_PUTFILE;
    out.buf = strerror(out.status);
    out.len = strlen(out.buf);
    send_reply(&out);

    if (fp) {
        fclose(fp);
    }

    return ret;
}

static int do_quitexe(char *line)
{
    int ret = 0;
    s_protocol_out out;
    char buf[32];

    snprintf(buf, sizeof(buf), "kill -9 %d", g_pid);
    int rc = system(buf);
    if (rc == -1) {
        ret = -errno;
    } else if (WIFSIGNALED(rc)) {
        ret = -EINTR;
    } else if (WIFEXITED(rc)) {
        ret = WEXITSTATUS(rc);
    } else {
        ret = -EIO;
    }

    memset(&out, 0, sizeof(s_protocol_out));
    out.session = g_session;
    out.status = -ret;
    out.command = CMD_TYPE_QUITEXE;
    out.buf = strerror(out.status);
    out.len = strlen(out.buf);
    send_reply(&out);

    return ret;
}

static int do_command(char *line)
{
    int ret;
    s_protocol_in in;
    s_protocol_out out;

    /* Save cmd to log */
    fprintf(g_lfp, "client: %s", line);
    fflush(g_lfp);

    ret = __parse_message(line, &in);
    if (ret && in.session != g_session) {
        goto err;
    }

    size_t outline = 0;
    unsigned char *outstr = base64_decode((void *)in.buf, in.len + 1, &outline);
    if (outstr == NULL) {
        ret = -ENOMEM;
        goto err;
    }

    switch(in.command) {
    case CMD_TYPE_SHELLCMD:
        ret = do_shellcmd((char *)outstr);
        break;
    case CMD_TYPE_QUITEXE:
        ret = do_quitexe((char *)outstr);
        break;
    case CMD_TYPE_PUTFILE:
        ret = do_putfile((char *)outstr);
        break;
    default:
        /* illegal command */
        ret = -EPERM;
        break;
    }
    
    /* Decode memory */
    free(outstr);

    if (ret == 0) {
        /* Terminate the connection. */
        return 0;
    }

err:
    memset(&out, 0, sizeof(s_protocol_out));
    out.session = g_session;
    out.status = -ret;
    out.command = CMD_TYPE_UNKNOWN;
    out.buf = strerror(out.status);
    out.len = strlen(out.buf);
    send_reply(&out);

    return ret;
}

static int do_process(int ifd, int ofd)
{
    s_protocol_out out;

    g_ifp = fdopen(ifd, "r");
    if (!g_ifp) {
        perror("fdopen");
        exit(errno);
    }

    g_ofp = fdopen(ofd, "w");
    if (!g_ofp) {
        perror("fdopen");
        exit(errno);
    }

    /* Send handshake */
    char __buf[32];
    memset(&out, 0, sizeof(s_protocol_out));
    out.session = g_session;
    out.status = 0;
    out.command = CMD_TYPE_HANDSHAKE;
    out.buf = __buf;
    snprintf(__buf, sizeof(__buf), "pid = %d", getpid());
    out.len = strlen(out.buf);
    send_reply(&out);

    signal(SIGALRM, __timeout);
    alarm(g_timeout);

    /* Loop */
    while (1) {
        /* Reset time count */
        alarm(g_timeout);

        char * line = NULL;
        size_t linelen = 0;
        ssize_t n = getline(&line, &linelen, g_ifp);
        if (n < 0) {
            if (line) free(line);
            /* Client disconnect */
            __cleanup(0);
        }

        do_command(line);
        fflush(g_ofp);
    }

    return 0;
}

static int init_server()
{
    struct sockaddr_in serv_addr;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(errno);
    }

    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(g_portno);

    /* Reuse addr */
    int on = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        exit(errno);
    }

    /* Save socket fd */
    g_sockfd = sockfd;

    /* Server daemonizes if necessary */
    do_daemon();

    return 0;
}

static int start_server()
{
    struct sockaddr_in cli_addr;

    /* Now start listening for the clients */
    listen(g_sockfd, SOMAXCONN);

    while (1) {
        socklen_t clilen = sizeof(cli_addr);
        int newsockfd = accept(g_sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0) {
            perror("accept");
            sleep(2);
            continue;
        }

        /* Add session count */
        g_session++;

        /* Create child process */
        int pid = fork();
        if (pid < 0) {
            perror("fork");
            close(newsockfd);

            /* Just let it continue here */
            sleep(2);
            continue;
        }

        if (pid == 0) {
            close(g_sockfd);

            /* The second fork() will dettach the cmdline child process */
            int pid2 = fork();
            if (pid2 == 0) {
                /* Prepare log record */
                do_verbose();
                /* Process cmd */
                do_process(newsockfd, newsockfd);
            }
            _exit(0);
        } else {
            close(newsockfd);
            int status;
            wait(&status);
            if (status != 0)
                perror("wait");
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    parse_config(argc, argv);

    init_server();

    start_server();

    return 0;
}
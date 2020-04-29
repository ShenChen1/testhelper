#!/usr/bin/env python

import argparse
import sys
import os
import socket
import threading
import logging
import re
import base64

class th_client(object):

    def __init__(self, verbose):
        # log config
        level = logging.ERROR if verbose == False else logging.DEBUG
        format = "PID[%(process)d]-[%(levelname)s]: %(message)s"
        logging.basicConfig(level=level, format=format)

        self.__blocksize = 4096
        self.__verbose = verbose
        self.__socket = None

        # cmd type
        self.__cmd_type_handshake = 'handshake'
        self.__cmd_type_shellcmd = 'shellcmd'
        self.__cmd_type_quitexe = 'quitexe'
        self.__cmd_type_putfile = 'putfile'
        self.__cmd_type_getfile = 'getfile'

        self.__cmd_handers = {}
        self.__cmd_handers[self.__cmd_type_shellcmd] = \
            { 'args_min':1, 'args_max':None, 'handler':self.__do_shellcmd }
        self.__cmd_handers[self.__cmd_type_quitexe] = \
            { 'args_min':0, 'args_max':0, 'handler':self.__do_quitexe }
        self.__cmd_handers[self.__cmd_type_putfile] = \
            { 'args_min':1, 'args_max':2, 'handler':self.__do_putfile }
        self.__cmd_handers[self.__cmd_type_getfile] = \
            { 'args_min':1, 'args_max':2, 'handler':self.__do_getfile }

    def __del__(self):
        if self.__socket:
            self.__socket.close()
        self.__socket = None

    def create_session(self, fhost):
        self.__fhost = fhost
        try:
            host, port = fhost.split(':', 1)
        except ValueError as msg:
            raise RuntimeError("ValueError:%s" % msg)
        logging.debug('session: host=%s port=%s', host, port)

        try:
            self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__socket.connect((host, int(port)))
        except socket.error as msg:
            raise RuntimeError(msg)

        # deal with handshake messsage
        buf = self.__getline(self.__socket)
        (session, status, command, bufstr) = self.__parse_message(buf)
        if command != self.__cmd_type_handshake:
            raise RuntimeError("CmdTypeError:%s" % command)
        self.__session = session

    def __do_shellcmd(self, cmdline):
        for cmd in cmdline:
            # send shell cmd
            self.__send_message(
                self.__socket,
                self.__session,
                self.__cmd_type_shellcmd,
                cmd + " 2>&1")

            # show the result
            buf = self.__getline(self.__socket)
            (session, status, command, bufstr) = self.__parse_message(buf)
            if command != self.__cmd_type_shellcmd:
                raise RuntimeError("CmdTypeError:%s" % command)

            bufstr = bufstr.strip()
            status = int(status)
            logging.info("Running '%s' ... " % cmd)
            if len(bufstr):
                print(bufstr)
            if status:
                sys.exit(status)

    def __do_quitexe(self, cmdline):
        # send quit cmd
        self.__send_message(
            self.__socket,
            self.__session,
            self.__cmd_type_quitexe,
            "quit")

    def __do_putfile(self, cmdline):
        # check the srcfile
        srcfile = cmdline[0]
        if os.path.isfile(srcfile) is False:
            raise RuntimeError("FileError:%s is not a file" % srcfile)

        # find the dstfile name
        dstfile = os.path.basename(srcfile)
        if len(cmdline) > 1:
            dstfile = cmdline[1]

        # get the srcfile file size
        length = os.path.getsize(srcfile)

        # send putfile cmd
        self.__send_message(
            self.__socket,
            self.__session,
            self.__cmd_type_putfile,
            "%s %s %s" % (srcfile, dstfile, length))

        # wait for reply
        buf = self.__getline(self.__socket)
        (session, status, command, bufstr) = self.__parse_message(buf)
        if command != self.__cmd_type_putfile:
            raise RuntimeError("CmdTypeError:%s" % command)
        elif status != "0":
            logging.error("[%s]: " % (status) + bufstr)
            raise RuntimeError("CmdTypeError:%s" % command)
        else:
            logging.info("Begin to send '%s' ... " % srcfile)

        # open
        file = open(srcfile, 'rb')
        if file is None:
            logging.error("Can't open %s " % srcfile)
            raise RuntimeError("open:%s" % srcfile)

        needed = length
        while needed > 0:
            buflen = min(self.__blocksize, needed)
            # read file
            buffer = file.read(buflen)
            assert len(buffer) == buflen
            # send data
            self.__send_message(
                self.__socket,
                self.__session,
                self.__cmd_type_putfile,
                buffer)
            needed -= buflen
            # recv ack
            buf = self.__getline(self.__socket)
            (session, status, command, bufstr) = self.__parse_message(buf)
            if command != self.__cmd_type_putfile:
                raise RuntimeError("CmdTypeError:%s" % command)
            elif status != "0":
                logging.error("[%s]: " % (status) + bufstr)
                raise RuntimeError("CmdTypeError:%s" % command)
            else:
                logging.info("Sending '%s' ... (%.02f %%)" % (srcfile, float(length - needed) / length * 100))

        # close file
        file.close()

    def __do_getfile(self, cmdline):
        # find the srcfile name
        srcfile = cmdline[0]
        # find the dstfile name
        dstfile = os.path.basename(srcfile)
        if len(cmdline) > 1:
            dstfile = cmdline[1]

        # send getfile cmd
        self.__send_message(
            self.__socket,
            self.__session,
            self.__cmd_type_getfile,
            "%s %s %lu" % (srcfile, dstfile, self.__blocksize))

        # wait for reply
        buf = self.__getline(self.__socket)
        (session, status, command, bufstr) = self.__parse_message(buf)
        if command != self.__cmd_type_getfile:
            raise RuntimeError("CmdTypeError:%s" % command)
        elif status != "0":
            logging.error("[%s]: " % (status) + bufstr)
            raise RuntimeError("CmdTypeError:%s" % command)
        else:
            logging.info("Begin to receive '%s' ... " % srcfile)
            # send ack
            self.__send_message(
                self.__socket,
                self.__session,
                self.__cmd_type_getfile,
                "continue")
        length = int(bufstr.strip('\0'))

        # create file
        file = open(dstfile, 'wb+')
        if file is None:
            logging.error("Can't open %s " % dstfile)
            raise RuntimeError("open:%s" % dstfile)

        needed = length
        while needed > 0:
            # recv data
            buf = self.__getline(self.__socket)
            (session, status, command, bufstr) = self.__parse_message(buf)
            if command != self.__cmd_type_getfile:
                raise RuntimeError("CmdTypeError:%s" % command)
            elif status != "0":
                logging.error("[%s]: " % (status) + bufstr)
                raise RuntimeError("CmdTypeError:%s" % command)
            else:
                needed -= len(bufstr)
                logging.info("Receiving '%s' ... (%.02f %%)" % (srcfile, float(length - needed) / length * 100))
            # write file
            file.write(bufstr)
            # send ack
            self.__send_message(
                self.__socket,
                self.__session,
                self.__cmd_type_getfile,
                "continue")

        # close file
        file.close()

    def run_command(self, cmds):
        try:
            cmd_hander = self.__cmd_handers[cmds[0]]
            # check args
            args_min = cmd_hander['args_min']
            args_max = cmd_hander['args_max']
            if len(cmds) - 1 < args_min or (args_max is not None and len(cmds) - 1 > args_max):
                raise RuntimeError("cmd range:" + cmds[1:])

            # run cmd handler
            cmd_hander['handler'](cmds[1:])
        except KeyError as msg:
            raise RuntimeError("KeyError:%s" % msg)

    @staticmethod
    def __send_message(socket, session, command, buf):
        # (session) {command} base64-buf
        data = '(%s) {%s} %s\n' % (session, command, base64.b64encode(buf))
        socket.send(data)
        data = '(%s) {%s} %s' % (session, command, buf)
        logging.debug('client: %s', data)

    @staticmethod
    def __getline(socket):
        file = socket.makefile('rb')
        data = file.readline()
        if data is None:
            logging.error('failure in recv, aborting')
            sys.exit(1)
        if len(data) == 0:
            logging.info('EOF')
            sys.exit(0)
        return data

    @staticmethod
    def __parse_message(buf):
        # (session) <status> {command} base64-buf
        pattern = re.compile(r"^\((\d+)\) \<(-?\d+)\> \{(\w+)\} (.*)\n$")
        match = pattern.match(buf)
        if match is None:
            raise RuntimeError("ValueError:%s" % buf)
        (session, status, command, bufstr) = match.groups()
        bufstr = base64.b64decode(bufstr)
        return (session, status, command, bufstr)

def main():
    parser = argparse.ArgumentParser(prog='testhelper', usage=\
          "%(prog)s [-v] host:port cmd ... \n" \
        + "     cmds:\n" \
        + "         shellcmd cmd ...\n" \
        + "         putfile lfile [rfile]\n" \
        + "         getfile rfile [lfile]\n" \
        + "         quitexe\n" \
        )
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose mode')
    parser.add_argument(dest='fhost', help='host:port')
    parser.add_argument(dest='cmds', nargs=argparse.REMAINDER, help='cmd ... ')
    args = parser.parse_args()

    try:
        client = th_client(args.verbose)
        client.create_session(args.fhost)
        client.run_command(args.cmds)

    except RuntimeError as e:
        logging.error('%s %s: %s' % (args.fhost, args.cmds, e))
        sys.exit(1)

if __name__ == '__main__':
    main()

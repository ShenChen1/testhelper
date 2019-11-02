#!/usr/bin/env python

import argparse
import sys
import socket
import threading
import logging
import re
import base64

class th_client(object):

    def __init__(self, verbose):
        if verbose == True:
            logging.basicConfig(level=logging.DEBUG)
        self.__verbose = verbose
        self.__socket = None

        # cmd type
        self.__cmd_type_handshake = 'handshake'
        self.__cmd_type_shellcmd = 'shellcmd'

        self.__cmd_handers = {}
        self.__cmd_handers[self.__cmd_type_shellcmd] = \
            { 'args_min':1, 'args_max':None, 'handler':self.__do_shellcmd }

    def __del__(self):
        if self.__socket:
            self.__socket.close()
        self.__socket = None

    def create_session(self, fhost):
        self.__fhost = fhost
        host, port = fhost.split(':', 1)
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
            raise Exception("Invalid cmd type!", command)
        self.__session = session
        
    def __do_shellcmd(self, cmdline):
            # send shell cmd
            self.__send_message(
                self.__socket, 
                self.__session, 
                self.__cmd_type_shellcmd,
                cmdline + " 2>&1")
            
            # show the result
            buf = self.__getline(self.__socket)
            (session, status, command, bufstr) = self.__parse_message(buf)
            print bufstr

    def run_command(self, cmds):
        if self.__cmd_handers[cmds[0]] != None:
            for cmd in cmds[1:]:
                self.__cmd_handers[cmds[0]]['handler'](cmd)
        else:
            raise Exception("Invalid cmd type!", cmds[0]) 

    @staticmethod
    def __send_message(socket, session, command, buf):
        # (session) {command} [len] base64-buf
        data = '(%s) {%s} %s\n' % (session, command, base64.b64encode(buf))
        socket.send(data)
        data = '(%s) {%s} %s\n' % (session, command, buf)
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
        pattern = re.compile(r"^\((\d+)\) \<(\d+)\> \{(\w+)\} (.*)\n$")
        (session, status, command, bufstr) = pattern.match(buf).groups()
        bufstr = base64.b64decode(bufstr)
        return (session, status, command, bufstr)

def main():
    parser = argparse.ArgumentParser(prog='testhelper', usage=\
          "%(prog)s [-v] host:port cmd ... \n" \
        + "     cmds:\n" \
        + "         shellcmd cmd ...\n" \
        + "         putfile lfile [rfile]\n" \
        + "         getfile rfile [lfile]\n" \
        + "         quit\n" \
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
        print '%s %s: %s' % (args.fhost, args.cmds, e)

if __name__ == '__main__':
    main()

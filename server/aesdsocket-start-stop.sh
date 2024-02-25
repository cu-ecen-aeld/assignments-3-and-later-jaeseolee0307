#!/bin/bash

DAEMON=/usr/bin/aesdsocket
NAME=aesdsocket
DESC="AESD Socket Application"

case "$1" in
    start)
        echo "Starting $DESC"
        start-stop-daemon --S -n aesdsocket -a aesdsocket -- -d
        ;;
    stop)
        echo "Stopping $DESC"
        start-stop-daemon start-stop-daemon -K -n aesdsocket
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac

exit 0

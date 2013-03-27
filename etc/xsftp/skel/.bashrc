# .bashrc

# User specific aliases and functions

# Source global definitions
if [ -f /etc/bashrc ]; then
	. /etc/bashrc
fi

if [ "$0" != "bash" ]
then
    /opt/fcombine/bin/shellmenu
    exit
fi


#!/bin/sh
# $Id: restart.sh,v 1.1 2004/02/25 16:29:05 tvierling Exp $

cd $(dirname $0)
kill $(cat milter.pid)
sleep 1

sh -c '
	export PMILTER_DISPATCHER=postfork
	echo $$ >milter.pid
	exec nice -n +4 perl -I../../lib ./milter.pl >milter.log 2>&1
' &

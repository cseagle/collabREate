#!/bin/sh

#the CLASSPATH should already be setup in the jar file, if not
#you can try something like:
#CLASSPATH=mysql-connector-java-5.1.13-bin.jar:postgresql-9.0-801.jdbc4.jar
#java -classpath $CLASSPATH -jar collabreate_server.jar $1 > /dev/null 2>&1 < /dev/null &

#or even execute the class files directly:
#java collabreate.server.CollabreateServer collabreate/server/example_server.conf

java -jar collabreate_server.jar server.conf > /dev/null 2>&1 < /dev/null &


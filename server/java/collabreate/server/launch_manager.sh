#!/bin/sh

#the CLASSPATH should already be setup in the jar file, if not
#you can try something like:
#CLASSPATH=mysql-connector-java-5.1.13-bin.jar:postgresql-9.0-801.jdbc4.jar
#java -classpath $CLASSPATH -jar collabreate_manager.jar $1

java -jar collabreate_manager.jar server.conf


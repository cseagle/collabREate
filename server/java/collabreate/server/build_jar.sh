#!/bin/sh

#take care of people having different versions of the JDBC connectors
#the jar manifest needs the correct file names
SQLJAR=`ls *mysql*.jar 2>/dev/null`
POSTGRESJAR=`ls *postgres*.jar 2>/dev/null`
MYCP="$SQLJAR $POSTGRESJAR"

echo "Using these JDBC connectors:$MYCP"

#create the manifest files 
echo "Main-Class: collabreate.server.CollabreateServer" > server_manifest.mf
echo "Class-Path: $MYCP" >> server_manifest.mf
echo "Name: collabreate/server/CollabreateServer/" >> server_manifest.mf
echo "Specification-Title: CollabREate Server" >> server_manifest.mf
echo "Specification-Version: 0.4.0" >> server_manifest.mf
echo "Specification-Vendor: Chris Eagle & Tim Vidas." >> server_manifest.mf
echo "Implementation-Title: CollabREate Server" >> server_manifest.mf
echo "Implementation-Version: Ida Qt" >> server_manifest.mf
echo "Implementation-Vendor: Chris Eagle & Tim Vidas" >> server_manifest.mf
echo "Implementation-URL: www.idabook.com/collabreate/" >> server_manifest.mf

echo "Main-Class: collabreate.server.ServerManager" > manager_manifest.mf
echo "Class-Path: $MYCP" >> manager_manifest.mf
echo "Name: collabreate/server/CollabreateServer/" >> manager_manifest.mf
echo "Specification-Title: CollabREate Server" >> manager_manifest.mf
echo "Specification-Version: 0.4.0" >> manager_manifest.mf
echo "Specification-Vendor: Chris Eagle & Tim Vidas." >> manager_manifest.mf
echo "Implementation-Title: CollabREate Server" >> manager_manifest.mf
echo "Implementation-Version: Ida Qt" >> manager_manifest.mf
echo "Implementation-Vendor: Chris Eagle & Tim Vidas" >> manager_manifest.mf
echo "Implementation-URL: www.idabook.com/collabreate/" >> manager_manifest.mf

#build the jar files
cd ../..
javac collabreate/server/*.java

jar cfm collabreate_server.jar collabreate/server/server_manifest.mf collabreate/server/*.class
mv -f collabreate_server.jar collabreate/server

jar cfm collabreate_manager.jar collabreate/server/manager_manifest.mf collabreate/server/*.class
mv -f collabreate_manager.jar collabreate/server

cd collabreate/server

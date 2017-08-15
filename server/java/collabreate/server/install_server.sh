#!/bin/sh

COLLAB_SCRIPT="${COLLAB_SCRIPT:-/usr/sbin/collabctl}"
COLLAB_LOG="${COLLAB_LOG:-/var/log/collab}"
INSTALL_DIR=/opt/collabreate/server
OPTIONS="Yes No"

# for those that actually use SELinux
if [ -x "/sbin/runuser" ]; then
    SU="/sbin/runuser"
else
    SU="su"
fi

echo "this script will install the collabreate server."
echo "Some options may require root privs (it might be easier to run this script as root)"
echo "continue?"
select o in $OPTIONS; do
  if [ "$o" = "Yes" ];
  then
   if [ ! -f "$COLLAB_LOG" ];
   then
     `$SU root -c "touch $COLLAB_LOG"`
     `$SU root -c "chgrp $COLLAB_USER $COLLAB_LOG"` 
     `$SU root -c "chmod 0664 $COLLAB_LOG"`
   fi
   if [ ! -f "$COLLAB_SCRIPT" ];
   then
     `$SU root -c "cp collabctl $COLLAB_SCRIPT"` 
     `$SU root -c "chmod 0555 $COLLAB_SCRIPT"`
   fi
   if [ ! -f "collabreate_server.jar" ] && [ -f "build_jar.sh" ];
   then
     echo "It looks like you haven't built the server jar file yet, should I try to build it?"
     select opt in $OPTIONS; do
       if [ "$opt" = "Yes" ];
       then
          ./build_jar.sh
          break
       fi
       if [ "$opt" = "No" ];
       then
          echo "the server jar is required for install, exiting"
          exit -1
       fi
     done
   fi

   if [ ! -f "server.conf" ];
   then
     echo "It looks like you haven't created a server.conf, you really should have one."
     echo "the server may not run as expected without the server.conf file"
   fi

   if [ -f "collabreate_server.jar" ];
   then
       echo "making directories"
      `$SU root -c "mkdir -p $INSTALL_DIR"`
       echo "copying server jar"
      `$SU root -c "cp collabreate_server.jar $INSTALL_DIR/collabreate_server.jar"`
      DBJAR=`ls *.jar | grep -i "mysql\|postgres"`
      for j in $DBJAR; do
         echo "copying db jar: $j"
         `$SU root -c "cp ./$j $INSTALL_DIR/"`
      done
      if [ -f "collabreate_manager.jar" ];
      then
        echo "copying manager jar"
        `$SU root -c "cp collabreate_manager.jar $INSTALL_DIR/collabreate_manager.jar"`
      else
        echo "can't find manager jar file.  It might not have built correctly."
        echo "continuing with install anyway - you won't be able to use the management interface."
      fi
      if [ ! -f $INSTALL_DIR"/server.conf" ];
      then
        echo "copying server.conf"
        `$SU root -c "cp server.conf $INSTALL_DIR/server.conf"` 
      else
        echo "Looks like you already have a server.conf installed, skipping"
      fi
      echo "do you want to install and configure init.d start/stop script? "
      select opt in $OPTIONS; do
        if [ "$opt" = "Yes" ];
        then
           if [ -f "fedora-init.d-script" ];
           then
             #quick check for fedora
             if [ -f "/etc/redhat-release" ] || [ -f "/etc/fedora-release" ];
             then
               echo "copying init.d script to /etc/init.d/collabreate"
               `$SU root -c "cp fedora-init.d-script /etc/init.d/collabreate"`
                 echo "changing permissions"
                 `$SU root -c "chmod 755 /etc/init.d/collabreate"`
               echo "chkconfig collabreate"
               `$SU root -c "chkconfig --add collabreate"`
             else
               echo "looks like you're not using fedora, the init.d script may work for you, "
               echo "but you'll have to install it manually"
             fi
           fi
           exit
        fi
        if [ "$opt" = "No" ];
        then
           exit
        fi
      done
   else
      echo "can't find server jar file.  Did it build correctly?"       
      echo "you might try to build the jar, see the README file"
      exit -1
   fi

  fi
  if [ "$o" = "No" ];
  then
     exit 0
  fi
done
exit 0

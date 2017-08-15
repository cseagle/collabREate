#!/bin/sh

# these are user configurable - but you should prob them across all aux files # 
SERVICE_NAME=collabreate
COLLAB_DB=collabDB
COLLAB_CONF=server.conf
IDENT="initdb"

# these can also be set via exported environmental variables                  #
# eg:  >INSTALLDIR=/usr/local/collabreate/server                              #
#      >export INSTALLDIR                                                     #
#      >make install                                                          #
# if you do set these via the environment, you should configure your system   #
# to always set them (other scripts depend upon the values of these variables)#
COLLAB_SERVER_DIR="${COLLAB_SERVER_DIR:-/opt/collabreate/server}"
COLLAB_LOG="${COLLAB_LOG:-/var/log/collab}"
COLLAB_SCRIPT="${COLLAB_SCRIPT:-/usr/sbin/collabctl}"
COLLAB_USER="${COLLAB_USER:-collab}"
COLLAB_GROUP="${COLLAB_GROUP:-collab}"
# end #

# for those that actually use SELinux
if [ -x "/sbin/runuser" ];
then
    SU="/sbin/runuser"
else
    SU="su"
fi

USERADD=`which adduser`

if [ -f "$COLLAB_SERVER_DIR/$COLLAB_CONF" ]; 
then
   LIKELYDB=`grep ^JDBC_NAME server.conf | grep -o "mysql\|postgresql"`
   echo "According to your installed server.conf file, you want to use: $LIKELYDB"
   echo "(if $LIKELYDB is not correct, you should exit and edit $COLLAB_SERVER_DIR/server.conf)"
elif [ -f "$COLLAB_CONF" ]; 
then
   LIKELYDB=`grep ^JDBC_NAME server.conf | grep -o "mysql\|postgresql"`
   echo "According to your local server.conf file, you want to use: $LIKELYDB"
   echo "(if $LIKELYDB is not correct, you should exit and edit server.conf)"
else
   LIKELYDB="postgresql"
   echo "Couldn't find your server.conf file, you really should have one..."
fi

echo "Select which database type you would like initialize for use with collabREate"
OPTIONS="MySQL PostgreSQL Exit"
select opt in $OPTIONS; do
   if [ "$opt" = "MySQL" ]; then
    echo "Initializing mysql..."
    echo "The account you are running as must have several mysql create permissions"
    echo "Do you want to continue ?"
     OPTIONS2="yes no"
     select opt2 in $OPTIONS2; do
	if [ "$opt2" = "yes" ]; then
	  echo "adding user $COLLAB_USER"
	  $SU -c "$USERADD $COLLAB_USER"
	  mysql < mysql/dbschema.sql 
	  echo "MySQL collabreate initialization done"
	  exit
	elif [ "$opt2" = "no" ]; then
	  exit
	else
	  echo "1 for 'yes' or 2 for 'no'"
	fi
     done
    exit
   elif [ "$opt" = "PostgreSQL" ]; then
    echo "adding user $COLLAB_USER"
    $SU -c "$USERADD $COLLAB_USER"
    echo "Initializing postgres..."
    #pg_hba.conf defaults to "ident sameuser" so -U doesn't work
    #however to su to users prior to psql commands, $COLLAB_USER must exist
    #as a local user....sigh, the follow attemps -U commands, then 
    #falls back to su style commands
    createuser -U postgres -s -d -R $COLLAB_USER
    if [ $? -ne 0 ];
    then
       $SU postgres -c "createuser -s -d -R $COLLAB_USER"
    fi
    createdb -U $COLLAB_USER $COLLAB_DB
    if [ $? -ne 0 ];
    then
       $SU $COLLAB_USER -c "createdb $COLLAB_DB"
    fi
    psql -q -U $COLLAB_USER -d $COLLAB_DB -f postgresql/dbschema.sql
    if [ $? -ne 0 ];
    then
       $SU $COLLAB_USER -c "psql -q -d $COLLAB_DB < postgresql/dbschema.sql"
    fi
    echo
    echo "Note:"
    echo "failures in the postgres init are usually due to issues"
    echo "with pg_hba.conf or system permissions"
    echo "ie 'ident sameuser' "
    exit
   elif [ "$opt" = "Exit" ]; then
    exit
   else
    echo "only options 1-3 are supported" 
   fi
done


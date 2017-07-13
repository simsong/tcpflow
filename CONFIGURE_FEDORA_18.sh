#!/bin/sh
cat <<EOF
*******************************************************************
Configuring Fedora 18 for cross-compiling multi-threaded 32-bit and
		 64-bit Windows programs with mingw.
*******************************************************************

This script will configure a fresh Fedora 18 system to compile with
mingw32 and 64.  It requires:

1. F18 installed and running. Typically you will do this by:

   1a - download the ISO for the 64-bit DVD (not the live media) from:
        http://fedoraproject.org/en/get-fedora-options#formats
   1b - Create a new VM using this ISO as the boot. The ISO will
        install off of its packages on your machine.
   1c - Start up Terminal; Chose Terminal's 
        Edit/Profile Preferences/Scrolling and check 'Unlimited' scrollback. 
   1d - Chose Applications/System Tools/System Settings/Screen.
        Select brightness 1 hour and Uncheck lock.
       
   NOTE: The first time you log in, the system will block the yum 
   system as it downloads updates. This is annoying.

2. This script. You have it. Put it in your home directory.

3. Root access. This script must be run as root. You can do that 
   by typing:
          sudo sh CONFIGURE_F18.sh

press any key to continue...
EOF
read

if [ $USER != "root" ]; then
  echo This script must be run as root
  exit 1
fi

if [ ! -r /etc/redhat-release ]; then
  echo This requires Fedora Linux
  echo Please download the Fedora 18 iso.
  echo Boot the ISO and chose System Tools / Install to Hard Drive.
  echo You will then need to:
  echo      sudo yum -y install subversion
  echo      svn co https://md5deep.svn.sourceforge.net/svnroot/md5deep
  echo Then run this script again.
  exit 1
fi

if grep 'Fedora.release.18' /etc/redhat-release ; then
  echo Fedora Release 18 detected
else
  echo This script is only tested for Fedora Release 18
  exit 1
fi

echo Adding packages to install list required to compile tcpflow under Fedora.

PKGS+="autoconf automake gcc gcc-c++ texinfo man-db man-pages "

echo Adding libraries required to compile tcpflow under Fedora.
PKGS+="zlib-devel zlib-static boost-devel boost-static cairo-devel "
PKGS+="libpcap-devel tre wget "

echo Adding wine for Windows testing:
PKGS+="wine "

echo "Now adding all of the packages that we will need: $PKGS"
if yum -y install $PKGS ; then
  echo "Installed all yummy packages"
else
  echo "Could not install all yummy packages"
  exit 1
fi

echo Adding mingw compilers...
for M in mingw32 mingw64 ; 
do
  PKGS = "${M}-gcc ${M}-gcc-c++"
  if yum -y install $PKGS ; then
    echo mingw compilers installed successfully
  else
    echo could not install mingw compilers
    exit 1
  fi
done

echo Attempting to install both DLL and static version of all mingw libraries
echo At this point we will keep going even if there is an error...
for M in mingw32 mingw64 ; 
do
  for lib in zlib gettext boost cairo pixman freetype fontconfig bzip2 expat pthreads libgnurx tre wpcap ; 
  do
    yum -y install ${M}-${lib}
    yum -y install ${M}-${lib}-static
  done
done


echo 
echo "Now performing a yum update to update system packages"
yum -y update

echo 
echo "Now installing packages which need to be installed manually"
wget http://www.freedesktop.org/software/fontconfig/release/fontconfig-2.10.92.tar.gz
tar xfz fontconfig-2.10.92.tar.gz
cd fontconfig-2.10.92
mingw32-configure
make ; make install ; make clean
mingw64-configure
make ; make install ; make clean

echo ================================================================
echo ================================================================
echo
echo You are now ready to compile windows binaries.


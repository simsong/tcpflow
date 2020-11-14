PACKAGES="emacs automake zlib zlib-static openssl-devel boost-devel cairo-devel libpcap-devel libpcap-devel cairo-devel gcc-c++ python-devel"
sudo yum install -y install $PACKAGES
sh bootstrap.sh
./configure --disable-dependency-tracking

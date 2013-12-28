. $srcdir/test-subs.sh

echo DMPDIR=$DMPDIR
echo TCPFLOW=$TCPFLOW

# check the results
checkmd5()
{
  if [ ! -r $1 ] ; 
  then 
     echo file $1 was not created
     ls -l
     exit 1
  fi

  md5val=`openssl md5 $1 | awk '{print $2;}'`
  if [ x$2 != x$md5val ];
  then 
     echo failure:         $1
     echo expected md5:    $2 "(got '$md5val')"
     echo expected length: $3
     ls -l $1
     exit 1
  fi
}

testmd5()
{
  md5val=`openssl md5 $1 | awk '{print $2;}'`
  len=`stat -r $1  | awk '{print $8;}'`
  echo checkmd5 \"$1\" \"$md5val\" \"$len\"
}

cmd()
{
    echo $1
    if ! $1 ; then echo failed; exit 1; fi
}
NITROBA=/corp/nps/packets/2008-nitroba/nitroba.pcap
if [ -r $NITROBA ]; then
  /bin/rm -rf out1
  cmd "$TCPFLOW -S netviz_max_histogram_size=1000 -S netviz_histogram_dump=1 -o out1 -r $NITROBA"
  /bin/rm -rf out1
else
  echo $NITROBA not present.
fi
exit 0


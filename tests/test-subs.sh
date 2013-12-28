case x"$srcdir" in 
  x)
    echo No srcdir specified. Assuming $0 is run locally
    DMPDIR=.
    TCPFLOW=../src/tcpflow
    ;;
  x.)
    echo srcdir is .  Assuming $0 is run locally from make check
    DMPDIR=.
    TCPFLOW=../src/tcpflow
    ;;
  *)
    echo srcdir is $srcdir Assuming $0 is run from make distcheck
    DMPDIR=../../tests/
    TCPFLOW=../../_build/src/tcpflow
    ;;
esac

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


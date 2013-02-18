#!/bin/sh
#
case x"$srcdir" in 
  x)
    echo No srcdir specified. Assuming $0 is run locally
    TCPFLOW=../src/tcpflow
    ;;
  x.)
    echo srcdir is .  Assuming $0 is run locally from make check
    TCPFLOW=../src/tcpflow
    ;;
  *)
    echo srcdir is $srcdir Assuming $0 is run from make distcheck
    TCPFLOW=../../_build/src/tcpflow
    ;;
esac


# create PDFs for all of the pcap files
for i in *.pcap
do
  echo $i
  cmd="$TCPFLOW -Fg -E netviz -o tmp$$ -r $i"
  echo $cmd
  $cmd
  mv tmp$$/report.pdf `basename $i .pcap`.pdf
  echo ""
  /bin/rm -rf tmp$$
done

  
#!/bin/sh
#
# test to make sure that we can process the packets normally
#

. $srcdir/test-subs.sh

for t in 1 2 3 
do
  echo 
  echo ========
  echo check $t
  echo ========
  # Run the program
  DMPFILE=$DMPDIR/test$t.pcap
  echo checking $DMPFILE
  if ! [ -r $DMPFILE ] ; then echo $DMPFILE not found ; fi
  /bin/rm -rf out

  cmd "$TCPFLOW -o out -X out/report.xml -r $DMPFILE"

  case $t in
  1)
  checkmd5 out/"074.125.019.101.00080-192.168.001.102.50956" "ae30a88136feb0655492bdb75e078643" "136"
  checkmd5 out/"074.125.019.104.00080-192.168.001.102.50955" "61051e417d34e1354559e3a8901d19d3" "2792"
  checkmd5 out/"192.168.001.102.50955-074.125.019.104.00080" "14e9c335bf54dc4652999e25d99fecfe" "655"
  checkmd5 out/"192.168.001.102.50956-074.125.019.101.00080" "78b8073093d107207327103e80fbdf43" "604"

  # Check the times
  if ! ls -l out/074.125.019.101.00080-192.168.001.102.50956 | grep '2008' >/dev/null ; 
  then
    echo utimes on packet files not properly set.
    exit 1
  fi
;;
  2)
  checkmd5 out/"010.000.000.001.09999-010.000.000.002.36559--42" "b7d0b9ee8a7c1ea94b6b43b5a3e0da83"
  checkmd5 out/"010.000.000.002.36559-010.000.000.001.09999--42" "c4b95c552616bda3e21d063e8ee2e332"
;;
  3)
;;
  4)
   checkmd5 out/2001:0:53aa:64c:422:2ece:a29c:9cf6.51391-2001:67c:1220:809::93e5:916.00080 2600d38f9524c66f190212bbdb6f3c96
   checkmd5 out/2001:0:53aa:64c:422:2ece:a29c:9cf6.51392-2001:67c:1220:809::93e5:916.00080 ea4d328b4c831f6cb54772bcaa206ad1
   checkmd5 out/2001:0:53aa:64c:422:2ece:a29c:9cf6.51393-2001:67c:1220:809::93e5:916.00080 775823553ec206c97c079ab054869c80
   checkmd5 out/2001:0:53aa:64c:422:2ece:a29c:9cf6.51394-2001:67c:1220:809::93e5:916.00080 4b12431fb1403ed45a0cdd264c555c21
   checkmd5 out/2001:0:53aa:64c:422:2ece:a29c:9cf6.51395-2001:67c:1220:809::93e5:916.00080 3a2c8438a3e42e617b0d134ae9bb2f0a
   checkmd5 out/2001:0:53aa:64c:422:2ece:a29c:9cf6.51396-2001:67c:1220:809::93e5:916.00080 547bdc57f5ac3bac3b6620afc19d5a00
   checkmd5 out/2001:67c:1220:809::93e5:916.00080-2001:0:53aa:64c:422:2ece:a29c:9cf6.51391 2a8f64558ad7a1731e4950a3f7f16913
   checkmd5 out/2001:67c:1220:809::93e5:916.00080-2001:0:53aa:64c:422:2ece:a29c:9cf6.51392 92e4df1f268a7f7b1244b4ddc67120d3
   checkmd5 out/2001:67c:1220:809::93e5:916.00080-2001:0:53aa:64c:422:2ece:a29c:9cf6.51393 873ce29539afc9bd72d65c11d9aef2f7
   checkmd5 out/2001:67c:1220:809::93e5:916.00080-2001:0:53aa:64c:422:2ece:a29c:9cf6.51394 c043c19025e6ba8278b7ddb6f08d68d3
   checkmd5 out/2001:67c:1220:809::93e5:916.00080-2001:0:53aa:64c:422:2ece:a29c:9cf6.51395 ca32de2d5504c6f8dc32610d94046106
   checkmd5 out/2001:67c:1220:809::93e5:916.00080-2001:0:53aa:64c:422:2ece:a29c:9cf6.51396 b4772e037e05aaf315aaad911a59650d
;;
  esac
  /bin/rm -f *.[0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9].*
  /bin/rm -f *.[0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]:*
  echo Packet file $t completed successfully
done

/bin/rm -rf out
exit 0

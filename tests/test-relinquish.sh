#!/bin/sh
#
# test -U / --relinquish-privileges
#

. $srcdir/test-subs.sh

DMPFILE=$DMPDIR/test1.pcap

for spec in "" ":" "+5" "1:-5" "4294967295" "99999999999999999999" \
            "tcpflow-no-such-user" ":tcpflow-no-such-group"
do
  if $TCPFLOW -U "$spec" -o out-relinquish -r $DMPFILE >/dev/null 2>relinquish.err ; then
    echo "failure: -U '$spec' was accepted"
    exit 1
  fi
  if ! grep -q -- "-U " relinquish.err ; then
    echo "failure: -U '$spec' failed for another reason:"
    cat relinquish.err
    exit 1
  fi
done
rm -rf out-relinquish relinquish.err
echo "invalid -U arguments are rejected"

if [ "`id -u`" != "0" ] ; then
  echo "not running as root; skipping ownership checks"
  exit 77
fi

WORK=`mktemp -d`
chmod 1777 $WORK
# inputs after the first -r are opened without root
cp $DMPFILE $WORK/test1.pcap
DMPFILE=$WORK/test1.pcap

owner()
{
  ls -lnd "$1" | awk '{print $3":"$4;}'
}

# check_owner <spec> <expected uid:gid>
check_owner()
{
  # $out and $unk are created by tcpflow as root, before dropping privileges
  out=$WORK/out-`echo "$1" | tr ':' '_'`
  unk=$out.unk.pcap
  cmd "$TCPFLOW -U $1 -o $out -X $out/report.xml -w $unk -r $DMPFILE"
  for f in $out $unk $out/report.xml $out/074.125.019.101.00080-192.168.001.102.50956 ; do
    got=`owner $f`
    if [ x"$got" != x"$2" ] ; then
      echo "failure: -U $1: $f is owned by $got, expected $2"
      rm -rf $WORK
      exit 1
    fi
  done
  echo "-U $1: files owned by $2"
}

check_owner 900:990 900:990
id 901 >/dev/null 2>&1 || check_owner 901 901:0
check_owner :991    0:991

# a numeric uid with a passwd entry gets its primary group
NOBODY_UID=`id -u nobody`
case "$NOBODY_UID" in
  ''|*[!0-9]*) ;;
  *) check_owner $NOBODY_UID $NOBODY_UID:`id -g nobody` ;;
esac

# privileges must be dropped only once, not again for the second -r
cmd "$TCPFLOW -U 900:990 -o $WORK/out-two -r $DMPFILE -r $DMPFILE"
echo "-U with two -r files works"

rm -rf $WORK
exit 0

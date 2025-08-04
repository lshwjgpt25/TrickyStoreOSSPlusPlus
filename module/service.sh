DEBUG=false

MODDIR=${0%/*}

cd $MODDIR

(
while [ true ]; do
  $MODDIR/daemon "$MODDIR"
  if [ $? -ne 0 ]; then
    exit 1
  fi
done
) &

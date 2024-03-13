cmd="./sipe"
count=30
for ((i=0;i<$count;i++))
do
$cmd --data.dir=./new-account  --password=./password.txt account new
done
androidPlatform=/home/sky/android-platforms
appPath=$1

cd ic3
./lauchIC3.sh $appPath
iccModelDir=`pwd`/OutDir

cd ..
f
for model in `ls $iccModelDir`
do
iccModel=$iccModelDir/$model
done

java -Xmx20g -Xms20g -jar guard.jar $appPath $androidPlatform $iccModel

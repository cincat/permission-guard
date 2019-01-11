#! /bin/sh

appPath=$1
forceAndroidJar=/home/sky/android-platforms/android-23/android.jar

rm -rf testspace
mkdir testspace

appName=`basename $appPath .apk`
retargetedPath=testspace/$appName.apk/retargeted/retargeted/$appName

rm -rf OutDir
mkdir OutDir

#rm -rf $retargetedPath
#mkdir $retargetedPath

java -Xmx24g -jar RetargetedApp.jar $forceAndroidJar $appPath $retargetedPath
java -Xmx24g -jar ic3-0.2.0-full.jar -apkormanifest $appPath -input $retargetedPath -cp $forceAndroidJar -protobuf OutDir

#rm -rf testspace
rm -rf sootOutput

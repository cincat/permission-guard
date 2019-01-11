#! /bin/sh

apkDir=/home/sky/apk-files-test
#apkDir=/home/sky/eclipse-workspace/permission-guard/temp
#apkDir=/home/sky/sootOutput

for app in `ls /$apkDir`
do
	#appPath="${apkDir}/${app}"
	timeout 30m sh testImpl.sh $apkDir/$app	
done

STAGE_SERVER=$1
STAGE_SERVER_IMAGE=$2
#sshpass -p $STAGE_PASSWORD | ssh  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null virsec@$STAGE_SERVER 'bash -s' < deploy/launch.sh saimohanczn/was-python:ci_cd-"$CI_BUILD_ID"
sshpass -p $STAGE_PASSWORD ssh  -o StrictHostKeyChecking=no virsec@$STAGE_SERVER 'bash -s' < deploy/launch.sh $STAGE_SERVER_IMAGE

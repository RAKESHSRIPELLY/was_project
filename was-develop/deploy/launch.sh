image=$1
containerName='python_was'
# Get image name from the container
previousDockerImage="$(docker inspect --format='{{.Config.Image}}' $containerName)"
# Download the image from registry
docker login -u $VREGISTRY_USER -p $VREGISTRY_PASS $VREGISTRY_URL
docker pull $image
# Remove previous container
docker rm -f $containerName

# Run the image on this port
docker run --restart unless-stopped -p 8000:8000 -p 8080:8080 --name $containerName  -d $image

# Remove the image which was used by the previous container
if test ! -z "$previousDockerImage" 
then
    docker rmi $previousDockerImage
fi
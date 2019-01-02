VERSION=0.1
SHARE=share
NAME=angr-fsm

all:	build-share run
	

build-share:
	mkdir -p ${SHARE}

run:
	sudo docker run --rm -ti --name=${NAME} -v `pwd`/${SHARE}:/home/ubuntu/share -h ubuntu ${NAME}-${VERSION}

clean:
	sudo docker rm ${NAME}-${VERSION}

build:
	-sudo docker rmi ${NAME}-${VERSION}
	sudo docker build -t ${NAME}-${VERSION} -f Dockerfile ../../

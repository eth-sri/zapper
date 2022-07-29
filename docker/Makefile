SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

PREREQUISITES_IMAGE := ethsrilab/zapper-prerequisites:0.0.1
ZAPPER_IMAGE := ethsrilab/zapper:0.0.1
CONTAINER := zapper

#######
# ZIP #
#######

.PHONY: anonymized-copy
anonymized-copy: copy
	cd zapper-copy && ../anonymize.sh ethsrilab sri

.PHONY: zip
zip: anonymized-copy
	rm -f zapper-implementation.zip
	cd zapper-copy && zip --quiet -r ../zapper-implementation.zip .

#########
# IMAGE #
#########

.PHONY: copy
copy:
	# copy sources to the zapper-copy directory
	rsync -a --delete --exclude docker/zapper-copy --exclude='/.git' --filter="dir-merge,- .gitignore" ../ ./zapper-copy/
	# extract dependencies
	cd ./zapper-copy/frontend && python3 setup.py egg_info

# build the docker image
.PHONY: prerequisites
prerequisites: copy
	docker build -t $(PREREQUISITES_IMAGE) --target zapper-prerequisites .

.PHONY: zapper
zapper: copy
	docker build -t $(ZAPPER_IMAGE) .

#######
# RUN #
#######

# launch a docker container using the image, which provides a shell in the
# container
.PHONY: run
run: zapper
	docker run -it --rm --name $(CONTAINER) $(ZAPPER_IMAGE) /bin/bash

##########
# DEPLOY #
##########

# Log in to the docker registry (needed to deploy the image)
.PHONY: login
login:
	docker login

# Deploy the image
.PHONY: deploy
deploy: login prerequisites
	docker push $(PREREQUISITES_IMAGE)

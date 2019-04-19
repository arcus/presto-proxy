PROG_NAME := presto-proxy
IMAGE_NAME := quay.research.chop.edu/arcus/$(PROG_NAME)

GIT_SHA := $(or $(shell git log -1 --pretty=format:"%h"), "latest")
GIT_TAG := $(shell git describe --tags --exact-match 2>/dev/null)
GIT_VERSION := $(shell git log -1 --pretty=format:"%h (%ci)")

ifndef BRANCH_NAME
	GIT_BRANCH := $(shell git symbolic-ref -q --short HEAD)
else
	GIT_BRANCH := $(BRANCH_NAME)
endif

GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)
GOPATH := $(shell go env GOPATH)

export GO111MODULE ?= on

nop:
	echo "No default target; pick one"

build:
	go build \
		-ldflags "-X \"main.buildVersion=$(GIT_VERSION)\" " \
		-o ./dist/$(GOOS)-$(GOARCH)/$(PROG_NAME) .

dist:
	GOOS=linux GOARCH=amd64 make build

image:
	docker build -t ${IMAGE_NAME}:${GIT_SHA} .
	docker tag ${IMAGE_NAME}:${GIT_SHA} ${IMAGE_NAME}:${GIT_BRANCH}

	if [ "${GIT_TAG}" != "" ] ; then \
		docker tag ${IMAGE_NAME}:${GIT_SHA} ${IMAGE_NAME}:${GIT_TAG} ; \
	fi;

	if [ "${GIT_BRANCH}" == "master" ]; then \
		docker tag ${IMAGE_NAME}:${GIT_SHA} ${IMAGE_NAME}:latest ; \
	fi;

push:
	docker push ${IMAGE_NAME}:${GIT_SHA}
	docker push ${IMAGE_NAME}:${GIT_BRANCH}

	if [ "${GIT_TAG}" != "" ]; then \
		docker push ${IMAGE_NAME}:${GIT_TAG} ; \
	fi;

	if [ "${GIT_BRANCH}" == "master" ]; then \
		docker push ${IMAGE_NAME}:latest ; \
	fi;

deploy:
	kubectl --context=presto apply -f k8s/deployment.yml

.PHONY: nop build dist image push

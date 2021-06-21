NAME=iptables-api
VERSION=0.0.1

ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

RELEASE_PACKAGE:=ldesplanche/$(NAME)

DOCKER_ARGS:=-v /var/run/docker.sock:/var/run/docker.sock -v ./compose:/compose -p 8082:8082

.PHONY: docker
docker:
	@docker run -v "$(ROOT_DIR)/src":"/web" $(DOCKER_ARGS) -p 8080:8080 --name "$(RELEASE_PACKAGE)_dev" --rm ldesplanche/marketplace_dev

.PHONY: release
release:
	@docker buildx create --use
	@docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 . -t $(RELEASE_PACKAGE) --push

.PHONY: docker-dev-image
docker-dev-image:
	@docker build -t $(RELEASE_PACKAGE)_dev - < dev.Dockerfile

.PHONY: build
## build: Compile the packages.
build:
	@go build -o $(NAME)

.PHONY: run
## run: Build and Run in development mode.
run: build
	@./$(NAME) -e dev

.PHONY: run-prod
## run-prod: Build and Run in production mode.
run-prod: build
	@./$(NAME) -e prod

.PHONY: clean
## clean: Clean project and previous builds.
clean:
	@rm -f $(NAME)

.PHONY: deps
## deps: Download modules
deps:
	@go mod download

.PHONY: test
## test: Run tests with verbose mode
test:
	@go test -v ./tests/*

.PHONY: help
all: help
# help: show this help message
help: Makefile
	@echo
	@echo " Choose a command to run in "$(APP_NAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo
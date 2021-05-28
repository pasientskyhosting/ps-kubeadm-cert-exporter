VERSION ?= "v1.1.0"
run:
	go run -race src/*.go

all: prep binaries docker

prep:
	mkdir -p bin

binaries: linux64

linux64:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/ps-kubeadm-cert-exporter64 src/*.go

pack-linux64: linux64
	upx --brute bin/ps-kubeadm-cert-exporter64

docker: pack-linux64
	docker build --build-arg version="$(VERSION)" -t pasientskyhosting/ps-kubeadm-cert-exporter:latest . && \
	docker build --build-arg version="$(VERSION)" -t pasientskyhosting/ps-kubeadm-cert-exporter:"$(VERSION)" .

docker-run:
	docker run pasientskyhosting/ps-kubeadm-cert-exporter:"$(VERSION)"

docker-push: docker
	docker push pasientskyhosting/ps-kubeadm-cert-exporter:"$(VERSION)"

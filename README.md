# PatientSky kubeadm-cert prometheus exporter

## Description
Monitor the expiration date of certificates generated by kubeadm


## Quickstart

### Step 1 - Setup env
You need these environment variables:
- `KUBE_DIR` - Kubernetes base directory (default: /etc/kubernetes/)
- `POLL_INTERVAL` - How often (in seconds) to check certificate expiration (default: 60)
- `METRICS_PORT` - Prometheus metrics port (default: 9598)

```
export KUBE_DIR=/etc/kubernetes/ && \
export POLL_INTERVAL=60 && \
export METRICS_PORT=9598
```

### Step 2 - Install dependencies

Install `dep` https://golang.github.io/dep/docs/installation.html

Run `dep ensure` in the `src` directory

### Step 3 - Build docker image and run

`make all` to build binaries and create the docker image

`make docker-run` to run the image


## Makefile
A makefile exists that will help with the following commands:

### Run
Compile and run with `make run`

### Build
Create binaries, upx pack and buld Docker image with `make all`

### Docker Run
Run docker image with `make docker-run`

### Docker Push
Push image to Docker hub with `make docker-push`
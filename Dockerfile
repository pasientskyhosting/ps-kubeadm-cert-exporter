FROM scratch
ENV PATH=/bin:/go/bin
# Copy our static executable.
COPY bin/ps-kubeadm-cert-exporter64 /go/bin/ps-kubeadm-cert-exporter
ENTRYPOINT ["/go/bin/ps-kubeadm-cert-exporter"]
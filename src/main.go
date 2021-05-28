package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v2"
)

var (
	kubeadmConf = []string{"admin.conf", "controller-manager.conf", "scheduler.conf", "kubelet.conf"}
	certStatus  = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeadm_cert_expiration",
			Help: "kubeadm-cert expiration",
		},
		[]string{"cert"})
)

type kubeadmCert struct {
	name       string
	expireTime int64
}

// Config Note: struct fields must be public in order for unmarshal to
// correctly populate the data.
type Config struct {
	APIVersion string `yaml:"apiVersion"`
	Clusters   []struct {
		Cluster struct {
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			Server                   string `yaml:"server"`
		} `yaml:"cluster"`
		Name string `yaml:"name"`
	} `yaml:"clusters"`
	Contexts []struct {
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
		Name string `yaml:"name"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
	Kind           string `yaml:"kind"`
	Preferences    struct {
	} `yaml:"preferences"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// Env ...
type Env struct {
	kubeDir      string
	pollInterval int
	metricsPort  string
}

func newEnv(
	kubeDir string,
	pollInterval int,
	metricsPort string) *Env {
	if kubeDir == "" {
		kubeDir = "/etc/kubernetes/"
	}
	if pollInterval == 0 {
		pollInterval = 60
	}
	if metricsPort == "" {
		metricsPort = "9598"
	}

	e := Env{
		kubeDir:      kubeDir,
		pollInterval: pollInterval,
		metricsPort:  metricsPort,
	}
	log.Printf("\tps-check-kubeadm-cert service started...")
	log.Printf("\tMetrics port: %s\n\n", e.metricsPort)

	return &e
}

// parse cert and return expiration date
func getCertExpiration(certPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, errors.New("Failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, errors.New("failed to parse certificate: " + err.Error())
	}
	return cert.NotAfter, nil
}

// check all certs and publish metrics
func checkCerts(e *Env) {
	ticker := time.NewTicker(time.Second * time.Duration(e.pollInterval)).C
	for {
		select {
		case <-ticker:
			kc := checkFileCert(e)
			cc := checkConfigCert(e)
			kc = append(kc, cc...)
			for _, cert := range kc {
				certStatus.WithLabelValues(cert.name).Set(float64(cert.expireTime))
			}
		}
	}
}

// check certs embedded in yaml files
func checkConfigCert(e *Env) []kubeadmCert {
	kc := []kubeadmCert{}
	for _, conf := range kubeadmConf {
		f, err := ioutil.ReadFile(e.kubeDir + conf)
		if err != nil {
			log.Fatal(err)
		}
		c := Config{}
		err = yaml.Unmarshal(f, &c)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		cert, err := base64.StdEncoding.DecodeString(c.Users[0].User.ClientCertificateData)
		expires, err := getCertExpiration(string(cert))
		if err != nil {
			log.Println(err)
		}
		kc = append(kc, kubeadmCert{name: conf, expireTime: expires.Unix()})
	}
	return kc
}

// check kubernetes .crt files
func checkFileCert(e *Env) []kubeadmCert {
	kc := []kubeadmCert{}
	files, err := ioutil.ReadDir(e.kubeDir + "pki")
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".crt" {
			f, err := ioutil.ReadFile(e.kubeDir + "pki/" + file.Name())
			if err != nil {
				log.Println(err)
			}
			expires, err := getCertExpiration(string(f))
			if err != nil {
				log.Println(err)
			}
			kc = append(kc, kubeadmCert{name: file.Name(), expireTime: expires.Unix()})
		}
	}
	return kc
}

// for integer environment variables
func getenvInt(key string) int {
	s := os.Getenv(key)
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}

func mainloop() {
	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal
	systemTeardown()
}

func systemTeardown() {
	log.Println("Shutting down...")
}

func main() {
	// get env
	e := newEnv(
		os.Getenv("KUBE_DIR"),
		getenvInt("POLL_INTERVAL"),
		os.Getenv("METRICS_PORT"),
	)
	go checkCerts(e)
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", e.metricsPort), nil))
	mainloop()
}

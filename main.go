package main

import (
	"context"
	"flag"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var clientset *kubernetes.Clientset

func main() {
	listenAddr := flag.String("listen", ":8080", "Address to listen on")
	k8sApiUrl := flag.String("master", "", "Kubernetes API URL")
	k8sKubeconfig := flag.String("kubeconfig", "", "Kubeconfig file")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	config, err := clientcmd.BuildConfigFromFlags(*k8sApiUrl, *k8sKubeconfig)
	if err != nil {
		logrus.Fatal(err)
	}

	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		logrus.Fatal(err)
	}

	http.HandleFunc("/auth", handleAuth)

	logrus.Printf("listening on %s", *listenAddr)

	if err := http.ListenAndServe(*listenAddr, nil); err != nil {
		logrus.Fatal(err)
	}
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if len(token) == 0 {
		logrus.Debug("Authorization header not supplied")
		http.Error(w, "Authorization header not supplied", http.StatusUnauthorized)

		return
	}

	audiencesRaw := r.URL.Query().Get("audience")
	if len(audiencesRaw) == 0 {
		logrus.Debug("audience query parameter not supplied")
		http.Error(w, "audience query parameter not supplied", http.StatusBadRequest)

		return
	}

	audiences := strings.Split(audiencesRaw, ",")

	allowed := strings.Split(r.URL.Query().Get("allowed"), ",")

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	authenticated, err := verifyToken(ctx, token, audiences, allowed)
	if err != nil {
		logrus.Errorf("error verifying token: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}
	if !authenticated {
		logrus.Debug("Invalid token")
		http.Error(w, "Invalid token", http.StatusForbidden)

		return
	}

	if _, err := io.WriteString(w, "{ \"authenticated\": true }"); err != nil {
		logrus.Errorf("error writing response: %v", err)
	}
}

func verifyToken(ctx context.Context, token string, audiences []string, allowed []string) (bool, error) {
	tr := authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: audiences,
		},
	}
	result, err := clientset.AuthenticationV1().TokenReviews().Create(ctx, &tr, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}

	sa := strings.TrimPrefix(result.Status.User.Username, "system:serviceaccount:")
	if result.Status.Authenticated && slices.Contains(allowed, sa) {
		return true, nil
	}

	return false, nil
}

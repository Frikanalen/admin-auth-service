# Go Authentication Service

This is a lightweight, general-purpose utility designed to securely restrict access to admin dashboards using Traefik's ForwardAuth middleware. It is written in Go and uses the `go-session` and `logrus` libraries for session management and logging respectively.

## Getting Started

These instructions will help you set up the service and run it on your local machine or a Kubernetes cluster.

#### Creating the Secret

If you are deploying the service for the first time, you need to create a Kubernetes secret to store `hash_key` and `password`. Here's how you can do it:

```bash
kubectl create secret generic <secret-name> --from-file=hash_key=<path-to-hash-key> --from-file=password=<path-to-password>
```
Replace <secret-name> with the name you want to give to your secret, <path-to-hash-key> with the path to your hash key file, and <path-to-password> with the path to your password file.

After creating the secret, you can install the Helm chart as described above.

### Building the Docker image

The provided Dockerfile allows you to build a Docker image of the service. Run the following command in the directory containing the Dockerfile:

```bash
docker build -t go-auth-service:latest .
```
Running the service
To run the service, use the following Docker command:

```bash
docker run -p 8080:8080 go-auth-service:latest
```
Kubernetes Deployment
The service is configured to read secrets from a Kubernetes secret, which should be mounted at /secrets. The secrets should include hash_key and password.

To update the Kubernetes secret, you can use the following one-liner:

```bash
kubectl patch secret <secret-name> -p='{"data":{"password": "'$(echo -n 'new-password' | base64)'"}}'
```

Just replace <secret-name> with the name of your secret and 'new-password' with the new password.

Remember to restart any pods that are using the secret to ensure they use the updated values.


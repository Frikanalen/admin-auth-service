# admin-auth-service
Microservice to authenticate users for admin dashboards

This is a Python Flask application that serves as an authentication service.
It uses Traefik's ForwardAuth mechanism to protect services behind a Traefik ingress controller.

## User database

This repository includes a utility script named mkhash.py that helps you generate user data in the format expected by the application.
When you run this script, it will prompt you for a username and password.
It will then hash the password and print out a line in the format username:passwordhash.
You can add this line to your user database file (users).
To run the script, use the following command: python mkhash.py.
 
## Environment Variables

The application uses the following environment variables:

- `ENV`: The environment in which the application is running. "development" or "production"
- `LOGIN_URL`: The URL to which the user is redirected if their session is not valid.

## Deployment

The application is deployed using Helm, a package manager for Kubernetes. To deploy the application, follow these steps:

1. Clone the repository:

```bash
git clone https://github.com/frikanalen/admin-auth-service.git
cd admin-auth-service
```

Install the Helm chart:

```bash
helm install admin-auth-service helm-chart/admin-auth-service
```
This will deploy the application with the default values. To customize the deployment, you can create a values.yaml file with your own values and pass it to the helm install command:

```bash
helm install admin-auth-service helm-chart/admin-auth-service -f my-values.yaml
```
Replace my-values.yaml with the path to your values.yaml file.

### Helm Configuration
The Helm chart has the following configurable values:

* replicaCount: The number of replicas of the application to run.
* image.repository: The Docker image repository.
* image.tag: The Docker image tag.
* image.pullPolicy: The Docker image pull policy.
* env: The environment in which the application is running.
* loginUrl: The URL to which the user is redirected if their session is not valid.
* resources: The resources to allocate to the application.
* service.type: The type of the service.
* service.port: The port of the service.
* ingress.enabled: Whether to create an Ingress for the application.
* ingress.hostname: The hostname for the Ingress.
* secretKey: The secret key for the Flask app. If not provided, a random key will be generated.

For more information on how to configure these values, see the values.yaml file in the helm-chart/admin-auth-service directory.

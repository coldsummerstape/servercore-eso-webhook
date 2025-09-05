# 🚀 Servercore Webhook - Simple Guide

**Webhook for integrating External Secrets Operator with Servercore Secrets Manager**

## 📖 What is this?

This project allows you to automatically fetch secrets from Servercore and create Kubernetes secrets from them using External Secrets Operator (ESO).

**💡 Servercore Secrets Manager service is provided for free!**

- **Configuration examples**: [examples/](./examples/)

## ⚡ Quick Start

### 1. Install External Secrets Operator with sidecar

```bash
# Add ESO repository
helm repo add external-secrets https://charts.external-secrets.io
helm repo update

# Install ESO with our webhook
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets-system \
  --create-namespace \
  -f examples/values-with-sidecar.yaml
```

### 2. Create secret with Servercore credentials

```bash
kubectl create secret generic servercore-credentials \
  --namespace external-secrets-system \
  --from-literal=username="YOUR_USERNAME" \
  --from-literal=password="YOUR_PASSWORD" \
  --from-literal=domain="YOUR_DOMAIN" \
  --from-literal=project="PROJECT_NAME"
```

**IMPORTANT**: 
- `domain` - **number in the top right corner** next to "account" in Servercore interface
- `project` - **project name** (not ID!)

### 3. Create ClusterSecretStore

```bash
kubectl apply -f examples/cluster-secret-store.yaml
```

## 🎯 How to use

### Step 1: Create a secret in Servercore

1. Go to Servercore Secrets Manager
2. Create a new secret with a name (e.g., `my-app-config`)
3. **IMPORTANT**: In the "Value" field, insert JSON directly:

```json
{
  "api_key": "sk_live_1234567890abcdef",
  "database_url": "postgresql://user:password@db.example.com:5432/myapp",
  "jwt_secret": "super-secret-jwt-key",
  "webhook_url": "https://hooks.example.com/webhook/abc123"
}
```

### Step 2: Create ExternalSecret

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: my-app-secrets
  namespace: default
spec:
  refreshInterval: 2h
  secretStoreRef:
    name: servercore-webhook-backend
    kind: ClusterSecretStore
  target:
    name: my-app-secrets
    creationPolicy: Owner
  data:
  - secretKey: api_key
    remoteRef:
      key: my-app-config  # Secret name in Servercore
      property: api_key   # Field from JSON
  - secretKey: database_url
    remoteRef:
      key: my-app-config
      property: database_url
  - secretKey: jwt_secret
    remoteRef:
      key: my-app-config
      property: jwt_secret
```

### Step 3: Use the secret in your application

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  containers:
  - name: app
    image: my-app:latest
    env:
    - name: API_KEY
      valueFrom:
        secretKeyRef:
          name: my-app-secrets
          key: api_key
    - name: DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: my-app-secrets
          key: database_url
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVERCORE_API_URL` | Servercore API URL | `https://cloud.api.selcloud.ru/secrets-manager/v1` |
| `SERVERCORE_AUTH_URL` | Authentication URL | `https://cloud.api.servercore.com/identity/v3/auth/tokens` |
| `SERVERCORE_USERNAME` | Username | - |
| `SERVERCORE_PASSWORD` | Password | - |
| `SERVERCORE_DOMAIN_NAME` | **Number in the top right corner** next to "account" | - |
| `SERVERCORE_PROJECT_NAME` | **Project name** (not ID!) | - |

### Docker Images

- `ghcr.io/coldsummerstape/servercore-eso-webhook:latest` - latest version
- `ghcr.io/coldsummerstape/servercore-eso-webhook:v1.0.0` - specific version

## 🏗️ Architecture

```
ESO → Webhook Sidecar → Servercore API
  ↑                    ↓
  └─── Kubernetes Secret
```

1. ESO sends request to sidecar with secret key
2. Sidecar calls Servercore API to fetch secret
3. Sidecar returns structured JSON response
4. ESO processes response and creates Kubernetes Secret

## 🚨 Important Notes

1. **JSON in Servercore**: Insert JSON directly in the "Value" field - no encoding needed
2. **Field names**: Use exact field names from JSON in ExternalSecret
3. **Secret updates**: ESO automatically updates secrets according to `refreshInterval`
6. **Domain and project in Servercore**: 
   - `domain` - **number in the top right corner** next to "account"
   - `project` - **project name** (not ID!)

**Done!** Now your secrets from Servercore will automatically sync with Kubernetes. 🎉

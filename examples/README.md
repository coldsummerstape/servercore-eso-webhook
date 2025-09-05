# Examples

This directory contains example configurations for using the Servercore webhook with External Secrets Operator.

## Files

- `cluster-secret-store.yaml` - Example ClusterSecretStore configuration
- `test-external-secret.yaml` - Example ExternalSecret configuration  
- `values-with-sidecar.yaml` - Example ESO Helm values with sidecar configuration
- `config/` - Secret configuration examples
- `crd/` - Kubernetes CRD examples

## Quick Start

1. Deploy ESO with sidecar using `values-with-sidecar.yaml`
2. Create ClusterSecretStore using `cluster-secret-store.yaml`
3. Create ExternalSecret using `test-external-secret.yaml`
4. Follow `config/SECRET_SETUP.md` to create secrets in Servercore

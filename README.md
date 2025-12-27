<!-- <p align="center">
<img src="/src/frontend/static/icons/Hipster_HeroLogoMaroon.svg" width="300" alt="MediCloudX Store" />
</p> -->

> [!WARNING]
> **🚨 CYBERSECURITY LABORATORY - CONTAINS INTENTIONAL VULNERABILITIES 🚨**
> 
> This project is designed for **cybersecurity education and penetration testing practice**. It contains **deliberately introduced security vulnerabilities** and should **NEVER be deployed in production environments**.
> 
> **Based on:** [GoogleCloudPlatform/microservices-demo](https://github.com/GoogleCloudPlatform/microservices-demo) with security modifications for educational purposes.

---

**🏆 HackTheCloud 25 Challenge**

This project is part of the main challenge of **HackTheCloud 25**, organized by the **Cloud Security Space**. Explore all challenges and resources at the main repository: [Spartan-Cybersecurity/HackTheCloud25](https://github.com/Spartan-Cybersecurity/HackTheCloud25)

**📋 Solutions & Walkthrough**: Need help? Check out [SOLUTIONS.md](./SOLUTIONS.md) for detailed exploitation techniques, vulnerability explanations, and security lessons learned.

---

**MediCloudX Store** is a cloud-first microservices demo application modified for cybersecurity training.  The application is a
web-based e-commerce app where users can browse items, add them to the cart, and purchase them - **with intentional security flaws for educational exploitation**.

Google uses this application to demonstrate how developers can modernize enterprise applications using Google Cloud products, including: [Google Kubernetes Engine (GKE)](https://cloud.google.com/kubernetes-engine), [Cloud Service Mesh (CSM)](https://cloud.google.com/service-mesh), [gRPC](https://grpc.io/), [Cloud Operations](https://cloud.google.com/products/operations), [Spanner](https://cloud.google.com/spanner), [Memorystore](https://cloud.google.com/memorystore), [AlloyDB](https://cloud.google.com/alloydb), and [Gemini](https://ai.google.dev/). This application works on any Kubernetes cluster.

If you’re using this demo, please **★Star** this repository to show your interest!

**Note to Googlers:** Please fill out the form at [go/microservices-demo](http://go/microservices-demo).

## Architecture

**MediCloudX Store** is composed of 11 microservices written in different
languages that talk to each other over gRPC.

[![Architecture of
microservices](/docs/img/architecture-diagram.png)](/docs/img/architecture-diagram.png)

Find **Protocol Buffers Descriptions** at the [`./protos` directory](/protos).

| Service                                              | Language      | Description                                                                                                                       |
| ---------------------------------------------------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| [frontend](/src/frontend)                           | Go            | Exposes an HTTP server to serve the website. Does not require signup/login and generates session IDs for all users automatically. |
| [cartservice](/src/cartservice)                     | C#            | Stores the items in the user's shopping cart in Redis and retrieves it.                                                           |
| [productcatalogservice](/src/productcatalogservice) | Go            | Provides the list of products from a JSON file and ability to search products and get individual products.                        |
| [currencyservice](/src/currencyservice)             | Node.js       | Converts one money amount to another currency. Uses real values fetched from European Central Bank. It's the highest QPS service. |
| [paymentservice](/src/paymentservice)               | Node.js       | Charges the given credit card info (mock) with the given amount and returns a transaction ID.                                     |
| [shippingservice](/src/shippingservice)             | Go            | Gives shipping cost estimates based on the shopping cart. Ships items to the given address (mock)                                 |
| [emailservice](/src/emailservice)                   | Python        | Sends users an order confirmation email (mock).                                                                                   |
| [checkoutservice](/src/checkoutservice)             | Go            | Retrieves user cart, prepares order and orchestrates the payment, shipping and the email notification.                            |
| [recommendationservice](/src/recommendationservice) | Python        | Recommends other products based on what's given in the cart.                                                                      |
| [adservice](/src/adservice)                         | Java          | Provides text ads based on given context words.                                                                                   |
| [adminservice](/src/adminservice)                   | Go            | Provides server-side URL fetching capabilities for administrative purposes with security controls.                                 |
| [loadgenerator](/src/loadgenerator)                 | Python/Locust | Continuously sends requests imitating realistic user shopping flows to the frontend.                                              |

## Screenshots

| Home Page                                                                                                         | Checkout Screen                                                                                                    |
| ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| [![Screenshot of store homepage](/docs/img/online-boutique-frontend-1.png)](/docs/img/online-boutique-frontend-1.png) | [![Screenshot of checkout screen](/docs/img/online-boutique-frontend-2.png)](/docs/img/online-boutique-frontend-2.png) |

## Quickstart (GKE)

1. Ensure you have the following requirements:
   - [Google Cloud project](https://cloud.google.com/resource-manager/docs/creating-managing-projects#creating_a_project).
   - Shell environment with `gcloud`, `git`, and `kubectl`.
   - Docker Desktop (for building images)

2. Clone the latest major version.

   ```sh
   git clone --depth 1 --branch v0 https://github.com/Spartan-Cybersecurity/HackTheCloud25-gcp.git
   cd HackTheCloud25-gcp/
   ```

   The `--depth 1` argument skips downloading git history.

3. Set the Google Cloud project and region and ensure the Google Kubernetes Engine API is enabled.

   ```sh
   export PROJECT_ID=<PROJECT_ID>
   export REGION=us-central1
   gcloud services enable container.googleapis.com \
     --project=${PROJECT_ID}
   ```

   Substitute `<PROJECT_ID>` with the ID of your Google Cloud project.

4. Create a GKE cluster and get the credentials for it.

   ```sh
   gcloud container clusters create-auto medicloudx-store \
     --project=${PROJECT_ID} --region=${REGION}
   ```

   Creating the cluster may take a few minutes.

5. Deploy MediCloudX Store to the cluster.

   **For Apple Silicon Macs (M1/M2/M3) - Recommended:**
   ```sh
   ./build-setup.sh
   ```
   
   This script automatically:
   - Fixes all platform compatibility issues
   - Builds and pushes container images to your registry
   - Deploys all services to your cluster

   **For Intel Macs or other platforms:**
   ```sh
   skaffold run --default-repo=us-central1-docker.pkg.dev/${PROJECT_ID}/microservices-demo
   ```

   **Alternative deployment using pre-built images (if available):**
   ```sh
   kubectl apply -f ./release/kubernetes-manifests.yaml
   ```

6. Wait for the pods to be ready.

   ```sh
   kubectl get pods
   ```

   After a few minutes, you should see the Pods in a `Running` state:

   ```
   NAME                                     READY   STATUS    RESTARTS   AGE
   adservice-76bdd69666-ckc5j               1/1     Running   0          2m58s
   cartservice-66d497c6b7-dp5jr             1/1     Running   0          2m59s
   checkoutservice-666c784bd6-4jd22         1/1     Running   0          3m1s
   currencyservice-5d5d496984-4jmd7         1/1     Running   0          2m59s
   emailservice-667457d9d6-75jcq            1/1     Running   0          3m2s
   frontend-6b8d69b9fb-wjqdg                1/1     Running   0          3m1s
   loadgenerator-665b5cd444-gwqdq           1/1     Running   0          3m
   paymentservice-68596d6dd6-bf6bv          1/1     Running   0          3m
   productcatalogservice-557d474574-888kr   1/1     Running   0          3m
   recommendationservice-69c56b74d4-7z8r5   1/1     Running   0          3m1s
   redis-cart-5f59546cdd-5jnqf              1/1     Running   0          2m58s
   shippingservice-6ccc89f8fd-v686r         1/1     Running   0          2m58s
   ```

7. Access the web frontend in a browser using the frontend's external IP.

   ```sh
   kubectl get service frontend-external | awk '{print $4}'
   ```

   Visit `http://EXTERNAL_IP` in a web browser to access your instance of MediCloudX Store.

8. Congrats! You've deployed the default MediCloudX Store. To deploy a different variation of MediCloudX Store (e.g., with Google Cloud Operations tracing, Istio, etc.), see [Deploy MediCloudX Store variations with Kustomize](#deploy-online-boutique-variations-with-kustomize).

9. Once you are done with it, delete the GKE cluster.

   ```sh
   gcloud container clusters delete online-boutique \
     --project=${PROJECT_ID} --region=${REGION}
   ```

   Deleting the cluster may take a few minutes.

## Additional deployment options

- **Terraform**: [See these instructions](/terraform) to learn how to deploy MediCloudX Store using [Terraform](https://www.terraform.io/intro).
- **Istio / Cloud Service Mesh**: [See these instructions](/kustomize/components/service-mesh-istio/README.md) to deploy MediCloudX Store alongside an Istio-backed service mesh.
- **Non-GKE clusters (Minikube, Kind, etc)**: See the [Development guide](/docs/development-guide.md) to learn how you can deploy MediCloudX Store on non-GKE clusters.
- **AI assistant using Gemini**: [See these instructions](/kustomize/components/shopping-assistant/README.md) to deploy a Gemini-powered AI assistant that suggests products to purchase based on an image.
- **And more**: The [`/kustomize` directory](/kustomize) contains instructions for customizing the deployment of MediCloudX Store with other variations.

## Apple Silicon (M1/M2/M3) Troubleshooting

If you encounter platform-related build errors on Apple Silicon Macs, the project includes automated fixes:

1. **Automatic fix (recommended):**
   ```sh
   ./build-setup.sh
   ```

2. **Manual fix:**
   ```sh
   ./fix-all-platforms.sh  # Apply platform fixes
   skaffold run --default-repo=us-central1-docker.pkg.dev/${PROJECT_ID}/microservices-demo
   ```

**Common errors resolved:**
- `exec format error` in containers
- `protoc exited with code 139` in cartservice
- Cross-compilation issues between ARM64 and AMD64 architectures

## Documentation

- [Development](/docs/development-guide.md) to learn how to run and develop this app locally.

## Demos featuring MediCloudX Store


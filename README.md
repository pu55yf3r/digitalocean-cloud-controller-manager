# Kubernetes Cloud Controller Manager for DigitalOcean

[![Build Status](https://travis-ci.org/digitalocean/digitalocean-cloud-controller-manager.svg?branch=master)](https://travis-ci.org/digitalocean/digitalocean-cloud-controller-manager) [![Report Card](https://goreportcard.com/badge/github.com/digitalocean/digitalocean-cloud-controller-manager)](https://goreportcard.com/report/github.com/digitalocean/digitalocean-cloud-controller-manager)

`digitalocean-cloud-controller-manager` is the Kubernetes cloud controller manager implementation for DigitalOcean. Read more about cloud controller managers [here](https://kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller/). Running `digitalocean-cloud-controller-manager` allows you to leverage many of the cloud provider features offered by DigitalOcean on your Kubernetes clusters.

## Releases

Cloud Controller Manager follows [semantic versioning](https://semver.org/).
The current version is **`v0.1.28`**. This means that the project is still
under active development and may not be production-ready. The plugin will be
bumped to **`v1.0.0`** once the [DigitalOcean Kubernetes
product](https://www.digitalocean.com/products/kubernetes/) is released and
will continue following the rules below:

* Bug fixes will be released as a `PATCH` update.
* New features will be released as a `MINOR` update.
* Significant breaking changes make a `MAJOR` update.

Because of the fast Kubernetes release cycles, CCM (Cloud Controller Manager)
will **only** support the version that is _also_ supported on [DigitalOcean Kubernetes
product](https://www.digitalocean.com/products/kubernetes/). Any other releases
will be not officially supported by us.

## Getting Started

Learn more about running DigitalOcean cloud controller manager [here](docs/getting-started.md)!

_Note that this CCM is installed by default on [DOKS](https://www.digitalocean.com/products/kubernetes/) (DigitalOcean Managed Kubernetes), you don't have to do it yourself._

## Examples

Here are some examples of how you could leverage `digitalocean-cloud-controller-manager`:

* [loadbalancers](docs/controllers/services/examples/)
* [node labels and addresses](docs/controllers/node/examples/)

## Production notes

### do not modify DO load-balancers manually

When creating load-balancers through CCM (via `LoadBalancer`-typed Services), it is important that you **must not change the DO load-balancer configuration manually.** Such changes will eventually be reverted by the reconciliation loop built into CCM. One exception are load-balancer names which can be changed (see also [the documentation on load-balancer ID annotations](/docs/getting-started.md#load-balancer-id-annotations)).

Other than that, the only safe place to make load-balancer configuration changes is through the Service object.

### DO load-balancer entry port restrictions

For technical reasons, the ports 50053, 50054, and 50055 cannot be used as load-balancer entry ports (i.e., the port that the load-balancer listens on for requests). Trying to use one of the affected ports as a service port causes a _422 entry port is invalid_ HTTP error response to be returned by the DO API (and surfaced as a Kubernetes event).

The solution is to change the service port to a different, non-conflicting one.

## Development

### Basics

* Go: min `v1.12.x`

This project uses [Go modules](https://github.com/golang/go/wiki/Modules) for dependency management and employs vendoring. Please ensure to run `make vendor` after any dependency modifications.

After making your code changes, run the tests and CI checks:

```bash
make ci
```

### Run Locally

If you want to run `digitalocean-cloud-controller-manager` locally against a
particular cluster, keep your kubeconfig ready and start the binary in the main
package-hosted directory like this:

```bash
cd cloud-controller-manager/cmd/digitalocean-cloud-controller-manager
FAKE_REGION=fra1 DO_ACCESS_TOKEN=your_access_token go run main.go \
  --kubeconfig <path to your kubeconfig file>                     \
  --leader-elect=false --v=5 --cloud-provider=digitalocean
```

The `FAKE_REGION` environment variable takes a (valid) DigitalOcean region. It
is needed to keep `digitalocean-cloud-controller-manager` from trying to access
the DigitalOcean metadata service which is only available on droplets. Overall,
which region you choose should not matter a lot as long as you pick one.

You might also need to provide your DigitalOcean access token in
`DO_ACCESS_TOKEN` environment variable. The token does not need to be valid for
the cloud controller to start, but in that case, you will not be able to
validate integration with DigitalOcean API.

Please note that if you use a Kubernetes cluster created on DigitalOcean, there
will be a cloud controller manager running in the cluster already, so you local
one will compete for API access with it.

### Run Locally (optional features)

#### Add Public Access Firewall

If you want to add an additional firewall, that allows public access to your
cluster, you can run a command like this:

```bash
cd cloud-controller-manager/cmd/digitalocean-cloud-controller-manager
FAKE_REGION=fra1 DO_ACCESS_TOKEN=your_access_token            \
PUBLIC_ACCESS_FIREWALL_NAME=firewall_name                     \
PUBLIC_ACCESS_FIREWALL_TAGS=k8s,k8s:<cluster-uuid>,k8s:worker \
go run main.go                                                \
  --kubeconfig <path to your kubeconfig file>                 \                                     
  --leader-elect=false --v=5 --cloud-provider=digitalocean
```

The `PUBLIC_ACCESS_FIREWALL_NAME` environment variable allows you to pass in
the name of the firewall you plan to use in addition to the already existing
DOKS managed firewall. It is called public access because you can
allow access to ports in the NodePort range, whereas this isn't possible with
the default DOKS managed firewall. Not passing this in will cause your cluster
to resort to the default behavior of denying all access to ports in the 
NodePort range.

The `PUBLIC_ACCESS_FIREWALL_TAGS` environment variable refers to the tags
associated with the public access firewall you provide.

#### Expose Prometheus Metrics

If you are interested in exposing prometheus metrics, you can pass in a metrics
endpoint that will expose them. The command will look similar to this:

```bash
cd cloud-controller-manager/cmd/digitalocean-cloud-controller-manager
FAKE_REGION=fra1 DO_ACCESS_TOKEN=your_access_token \
METRICS_ADDR=<host>:<port> go run main.go          \
  --kubeconfig <path to your kubeconfig file>      \                                                
  --leader-elect=false --v=5 --cloud-provider=digitalocean
```

The `METRICS_ADDR` environment variable takes a valid endpoint that you'd
like to use to serve your Prometheus metrics. To be valid it should be in the
form `<host>:<port>`.

After you have started up CCM, run the following curl command to view the
Prometheus metrics output:

```bash
curl <host>:<port>/metrics
```

### Run Containerized

If you want to test your changes in a containerized environment, create a new
image with the version set to `dev`:

```bash
VERSION=dev make publish
```

This will create a binary with version `dev` and docker image pushed to
`digitalocean/digitalocean-cloud-controller-manager:dev`.

## Release a new version

To release a new version first bump the version:

```bash
make NEW_VERSION=v1.0.0 bump-version
```

Make sure everything looks good. Create a new branch with all changes:

```bash
git checkout -b release-<new version> origin/master
git commit -a -v
git push origin release-<new version>
```

After it's merged to master, tag the commit and push it:

```bash
git checkout master
git pull
git tag <new version>
git push --tags
```

Finally, [create a Github
release](https://github.com/digitalocean/digitalocean-cloud-controller-manager/releases/new) from
master with the new version and publish it:

```bash
make publish
```

This will compile a binary containing the new version bundled in a docker image pushed to
`digitalocean/digitalocean-cloud-controller-manager:<new version>`

## Contributing

At DigitalOcean we value and love our community! If you have any issues or would like to contribute, feel free to open an issue/PR and cc any of the maintainers below.

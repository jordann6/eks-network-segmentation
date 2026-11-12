"""AKS variant of the segmentation lab diagram.

Renders docs/architecture-azure.png with official Azure and Kubernetes icons
(mingrammer diagrams) and the official Cilium icon from the CNCF artwork repo
(docs/icons/cilium.png). Run from the repo root: python3 docs/diagram_azure.py
(needs graphviz `dot` on PATH).

Same colours as the EKS diagram. AKS has two platform endpoints a pod can
reach by default, the instance metadata service and the Azure wire server, and
both are measured as separate rows.
"""
import os

from diagrams import Cluster, Diagram, Edge
from diagrams.azure.compute import VM
from diagrams.azure.containers import KubernetesServices
from diagrams.azure.network import PublicIpAddresses
from diagrams.custom import Custom
from diagrams.k8s.compute import Pod
from diagrams.k8s.network import NetworkPolicy
from diagrams.onprem.client import User

ICON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons", "cilium.png")

graph_attrs = {"fontsize": "13", "bgcolor": "white", "pad": "0.5", "nodesep": "0.6", "ranksep": "1.1"}
node_attrs = {"fontsize": "11"}

ok = {"color": "forestgreen", "fontcolor": "forestgreen", "penwidth": "2"}
bad = {"color": "firebrick", "fontcolor": "firebrick", "style": "dashed"}

with Diagram(
    "Network segmentation lab on AKS: legitimate flows (green) and attacker reach (red, denied after hardening)",
    filename="docs/architecture-azure",
    show=False,
    direction="LR",
    graph_attr=graph_attrs,
    node_attr=node_attrs,
):
    operator = User("operator\n(scenario runner,\n/32 endpoint)")
    aks = KubernetesServices("AKS 1.36 control plane\n(public, /32 scoped,\nbring your own CNI)")

    with Cluster("lab subscription"):
        imds = VM("node IMDS\n169.254.169.254")
        wire = VM("Azure wire server\n168.63.129.16")
        nat = PublicIpAddresses("outbound\n(internet egress)")

        with Cluster("Cilium 1.20.4: cluster-pool IPAM, VXLAN, L7 + DNS proxy, Hubble"):
            cilium = Custom("Cilium identities\n+ Hubble flows", ICON)
            policy = NetworkPolicy("default deny +\nCiliumNetworkPolicy")

            with Cluster("ns: frontend"):
                fe = Pod("frontend\n(planted RCE,\nno RBAC, no token)")
            with Cluster("ns: backend"):
                api = Pod("api\nGET /api/orders only")
                db = Pod("db")
            with Cluster("ns: sensitive"):
                sens = Pod("sensitive")
            with Cluster("ns: egress-sim (stands in for the internet)"):
                exfil = Pod("HTTP exfil\nreceiver")
                dns = Pod("authoritative DNS\nexfil.lab.test")
            coredns = Pod("kube-dns")

    operator >> Edge(label="port-forward = foothold") >> fe
    operator >> aks

    fe >> Edge(label="GET /api/orders", **ok) >> api
    api >> Edge(label="5432", **ok) >> db

    fe >> Edge(label="L3/L4 drop", **bad) >> sens
    fe >> Edge(label="L3/L4 drop", **bad) >> exfil
    fe >> Edge(label="POST /api/admin/export\nL7 403", **bad) >> api
    fe >> Edge(label="marker.exfil.lab.test\nDNS proxy REFUSED", **bad) >> coredns
    coredns >> Edge(label="forwards zone", style="dotted") >> dns
    fe >> Edge(label="egressDeny", **bad) >> imds
    fe >> Edge(label="L3/L4 drop (finding)", **bad) >> wire
    fe >> Edge(label="L3/L4 drop", **bad) >> nat

    policy >> Edge(style="dotted", color="gray") >> cilium

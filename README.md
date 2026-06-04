# Game Streaming Infrastructure — Architecture Documentation

## Overview

This document describes the architecture for a cloud-based multiplayer game streaming platform built on Unreal Engine's Pixel Streaming technology. The system consists of a central **Matchmaker Server** (Debian 12) and a fleet of **GPU-enabled Windows Game Servers**, provisioned on demand via Terraform.

The matchmaker acts as the entry point for players. It inspects the current state of all game servers and redirects each incoming user to an idle Pixel Streaming instance, enabling scalable, browser-accessible game streaming without any client-side installation.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────┐
│           Matchmaker Server (Debian 12)      │
│                                              │
│  ┌─────────────────┐  ┌──────────────────┐  │
│  │ Matchmaker :9999│  │ Frontend Dashboard│  │
│  │ (nginx → HTTPS) │  │ (Next.js :3000)   │  │
│  └─────────────────┘  └──────────────────┘  │
│                                              │
│  ┌──────────────────────────────────────┐   │
│  │         Terraform Config              │   │
│  └──────────────────────────────────────┘   │
└──────────────────┬──────────────────────────┘
                   │ terraform apply
                   ▼
        ┌──────────────────────┐
        │  Startup Script (PS1) │
        │  - Set domain name    │
        │  - Provision SSL      │
        │  - Start 3 services   │
        └──────┬───────────────┘
               │ provisions N game VMs
    ┌──────────┼──────────────────────┐
    ▼          ▼          ▼           ▼
┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
│ Game   │ │ Game   │ │ Game   │ │ Game   │
│ Server │ │ Server │ │ Server │ │ Server │
│(Win)   │ │(Win)   │ │(Win)   │ │(Win)   │
├────────┤ ├────────┤ ├────────┤ ├────────┤
│Pixel   │ │Pixel   │ │Pixel   │ │Pixel   │
│Stream  │ │Stream  │ │Stream  │ │Stream  │
│Game Mgr│ │Game Mgr│ │Game Mgr│ │Game Mgr│
│(Python)│ │(Python)│ │(Python)│ │(Python)│
│Game Bin│ │Game Bin│ │Game Bin│ │Game Bin│
└────────┘ └────────┘ └────────┘ └────────┘
```

---

## Components

### 1. Matchmaker Server

**OS:** Debian 12
**GCP VM name:** `matchmaker-vm`
**Public IP:** `34.72.177.191`
**Purpose:** Central coordination node. Routes incoming players to idle game servers and provides an admin dashboard for managing the entire fleet.

The matchmaker is a standard component from Unreal Engine's Pixel Streaming infrastructure, extended with a custom frontend and Terraform-based provisioning tooling.

#### 1.1 Matchmaker Service

| Property | Value |
|---|---|
| Port | 9999 (internal) |
| Public URL | `https://kmidden.zayahdevelopment.com` |
| Protocol | HTTPS (SSL terminated at nginx) |
| Reverse proxy | nginx |

The matchmaker maintains awareness of all registered game server instances and their current state (idle / occupied). When a player connects to the public URL, the matchmaker selects an idle Pixel Streaming server and transparently redirects the player's browser session to it.

nginx is configured as a reverse proxy sitting in front of the matchmaker process, handling SSL termination and forwarding traffic from port 443 to port 9999.

#### 1.2 Frontend Dashboard

| Property | Value |
|---|---|
| Framework | Next.js |
| Port | 3000 (internal) |
| Public URL | `https://kmidden.zayahdevelopment.com/dashboard` |
| Process manager | systemd |

The frontend dashboard is a Next.js application running as a systemd service. It is accessible under the `/dashboard` path of the main domain, routed there by nginx.

**Dashboard capabilities:**

- **Binary updates** — Push new game binary versions to all Windows game VMs remotely.
- **Service control** — Start and stop game services across the entire fleet from a single interface.
- **Fleet statistics** — Real-time visibility into the state of each VM (online/offline, CPU/GPU load, memory).
- **Player metrics** — View current active players per VM, cumulative total playtime, and per-session data.
- **Domain overview** — List all assigned subdomains and their corresponding game server instances.

#### 1.3 Terraform Configuration

The matchmaker server hosts the Terraform project used to programmatically provision and tear down game server VMs in the cloud.

**Location on matchmaker server:** `/home/freelance/terraform`

Terraform manages the full lifecycle of each game server:

- Spawning VMs from a pre-built Windows image (see section 2).
- Assigning public IP addresses to each VM.
- Creating DNS zone records and subdomains (e.g., `game01.example.com`, `game02.example.com`).
- Passing the VM-specific configuration (domain name) into the startup script at provision time.

##### variables.tf

All deployment parameters are centralized in `variables.tf`. This is the primary file to edit before running `terraform apply`.

```hcl
variable "project_id" {
  type    = string
  default = "clear-column-483714-j4"
}

variable "region" {
  type    = string
  default = "europe-west3"
}

variable "domain" {
  type    = string
  default = "zayahdevelopment.com"
}

variable "vm_count" {
  type    = number
  default = 3
}

variable "windows_image" {
  type    = string
  default = "uegame-007"
}
```

| Variable | Description |
|---|---|
| `project_id` | GCP project to deploy resources into. |
| `region` | GCP region for the game server VMs. Change this if the target region has no GPU quota available (see note below). |
| `domain` | Base domain used when generating per-VM subdomains. |
| `vm_count` | **Number of game server VMs to provision.** This is the most commonly adjusted variable — increase or decrease it to scale the fleet. |
| `windows_image` | Name of the pre-built GCP Windows image to use as the VM base. Update this when a new game image is built. |

> **Note on GPU availability — GCP region quotas**
>
> GCP can run out of NVIDIA L4 GPU capacity in a given region. If `terraform apply` fails with a quota or resource availability error, switch `region` to a zone that has L4 inventory. To find available zones for the NVIDIA L4:
>
> ```bash
> gcloud compute accelerator-types list --filter="name=nvidia-l4" --format="table(zone, name)"
> ```
>
> Pick a zone from the output (e.g., `us-central1-a`), extract the region prefix (e.g., `us-central1`), and update `region` in `variables.tf` accordingly before re-running `terraform apply`.

---

### 2. Game Servers

**OS:** Windows Server (GPU-enabled)
**Count:** Variable (provisioned on demand via Terraform)
**Base image:** Pre-built Windows snapshot containing all three required services pre-installed.

Each game server is a GPU-accelerated cloud VM. GPU access is required to run Unreal Engine's Pixel Streaming encoder, which captures the game rendering output and streams it as a video feed to the player's browser over WebRTC.

All game servers are provisioned from a shared base image, which already contains the game binary, the Pixel Streaming server, and the Game Manager. No manual software installation is needed after provisioning.

#### 2.1 Services Running on Each Game Server

Each VM runs three services concurrently, all started by the PS1 startup script during initial provisioning:

**Service 1: Game Binary**

The compiled Unreal Engine game executable. It runs headlessly and renders the game scene to an offscreen buffer that the Pixel Streaming plugin captures.

**Service 2: Pixel Streaming Server**

Unreal Engine's built-in Pixel Streaming frontend and signalling server. It establishes a WebRTC session with the player's browser and streams the GPU-rendered game frames in real time. The player's input (keyboard, mouse, gamepad) is sent back through the same WebRTC data channel.

**Service 3: Game Manager (Python)**

A Python-based agent that handles remote management tasks issued by the Frontend Dashboard. Responsibilities include:

- Accepting game binary update payloads from the dashboard.
- Starting and stopping the game and streaming services on command.
- Reporting health metrics (player count, uptime, resource usage) back to the dashboard.

---

### 3. Provisioning Flow

The end-to-end provisioning process for a new game server is as follows:

#### Step 1 — Terraform Apply

From the matchmaker server, an operator runs `terraform apply`. Terraform reads the configuration stored on the matchmaker and calls the cloud provider API to:

1. Create a new Windows VM instance from the pre-built base image.
2. Attach a GPU to the VM.
3. Allocate a public IP address.
4. Create a DNS A record (e.g., `game01.example.com`) pointing to the new IP.
5. Register the VM's domain in the matchmaker's server list.

#### Step 2 — PS1 Startup Script

Terraform injects a PowerShell startup script (`startup.ps1`) that runs automatically on first boot. The script performs three tasks:

1. **Set domain name** — Configures the VM's hostname and internal domain references to match the assigned subdomain (e.g., `game01.example.com`).
2. **Provision SSL** — Requests and installs a TLS certificate for the VM's subdomain, enabling encrypted Pixel Streaming signalling and Game Manager API traffic.
3. **Start all three services** — Launches the Game Binary, Pixel Streaming Server, and Game Manager (Python) as Windows services or background processes.

Once the startup script completes, the game server registers itself with the matchmaker and becomes available to receive players.

---

## Network & Domain Layout

| Endpoint | Purpose |
|---|---|
| `https://kmidden.zayahdevelopment.com` | Player entry point — matchmaker |
| `https://kmidden.zayahdevelopment.com/dashboard` | Admin dashboard |
| `https://game01.example.com` | Game Server 1 (Pixel Streaming) |
| `https://game02.example.com` | Game Server 2 (Pixel Streaming) |
| `https://gameNN.example.com` | Game Server N (Pixel Streaming) |

All subdomains are managed in the cloud provider's DNS zone by Terraform. SSL certificates are provisioned per VM via the PS1 startup script.

---

## Deployment Considerations

**Scaling up** — Run `terraform apply` with an increased instance count. New VMs bootstrap automatically and register with the matchmaker.

**Scaling down** — Run `terraform destroy` targeting specific instances, or reduce the count and re-apply. Ensure no active player sessions exist on the targeted VMs before destruction.

**Game binary updates** — Use the Frontend Dashboard to push a new binary to all (or selected) VMs. The Game Manager service on each VM handles the download, replacement, and service restart.

**SSL renewal** — Certificates are provisioned on first boot. Renewal should be automated (e.g., via a scheduled task or cron equivalent on each Windows VM) to avoid expiry.

**Matchmaker availability** — The matchmaker is a single point of failure for player routing. Consider placing it behind a load balancer or configuring a hot standby if uptime SLAs require it.

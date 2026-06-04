provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_compute_address" "game_ips" {
  count  = var.vm_count
  name   = "game-ip-${count.index + 1}"
  region = var.region
}

resource "google_compute_instance" "game_vm" {
  count        = var.vm_count
  name         = format("game%02d", count.index + 1)
  machine_type = "g2-standard-8"
  zone	       = "europe-west3-b"
  boot_disk {
    initialize_params {
      image = var.windows_image
      size  = 50
      type  = "pd-standard"
    }
  }

  tags = [
    "http-server",
    "https-server",
    "lb-health-check"
  ]
  guest_accelerator {
    type  = "nvidia-l4"
    count = 1
  }

  network_interface {
    network = "default"

    access_config {
      nat_ip = google_compute_address.game_ips[count.index].address
    }
  }

  metadata = {
      windows-startup-script-ps1 = templatefile("${path.module}/startup.ps1", {
      domain = var.domain
    })
  }

  scheduling {
    on_host_maintenance = "TERMINATE"
  }
}

resource "google_dns_record_set" "game_dns" {
  count        = var.vm_count
  name         = format("game%02d.%s.", count.index + 1, var.domain)
  managed_zone = "zayahdevelopment"
  type         = "A"
  ttl          = 60

  rrdatas = [
    google_compute_address.game_ips[count.index].address
  ]
}

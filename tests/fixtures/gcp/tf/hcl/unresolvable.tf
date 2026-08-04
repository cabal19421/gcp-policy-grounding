# unresolvable.tf -- one construct per unresolvable class, each on its OWN
# resource so a test can name it, and each carrying a comment that states the
# Unresolved.reason the reader must report for it.
#
# Nothing in this file is meant to resolve. That is the point: every construct
# here is a value a static reader CANNOT know without running terraform, and
# the contract is that it says so -- with the stated reason -- rather than
# guessing a value or dropping the object on the floor. The fully resolvable
# corpus is main.tf next door.
#
# These are still POSITIVE fixtures: the file is well-formed HCL describing
# plausible terraform. Degenerate and malformed inputs belong in tmp_path.

variable "x" {
  type = string
}

variable "tier" {
  type = string
}

variable "cidr" {
  type = string
}

variable "enabled" {
  type = bool
}

variable "blocked_ranges" {
  type = list(string)
}

locals {
  net = "projects/acme-prod/global/networks/vpc-main"
}

data "google_project" "this" {
  project_id = "acme-prod"
}

module "net" {
  source = "./modules/net"
}

provider "google" {
  alias   = "eu"
  project = "acme-eu"
  region  = "europe-west1"
}

# -- interpolation ------------------------------------------------------------

# reason: interpolation -- the WHOLE value is a variable reference, so the
# name this rule will carry is not in the configuration at all.
resource "google_compute_firewall" "whole_value_interpolation" {
  name    = "${var.x}"
  project = "acme-prod"
  network = "projects/acme-prod/global/networks/vpc-main"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# reason: interpolation -- a literal PREFIX and SUFFIX around the reference do
# not make the value resolvable. "roles/" plus ".admin" is not a role, and a
# reader that stripped the interpolation would invent one.
resource "google_project_iam_binding" "partial_interpolation" {
  project = "acme-prod"
  role    = "roles/${var.tier}.admin"
  members = ["user:alice@acme.example"]
}

# reason: interpolation -- a local value is defined elsewhere in the module
# and is not resolved by the HCL reader.
resource "google_compute_firewall" "local_reference" {
  name    = "local-reference"
  project = "acme-prod"
  network = local.net

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# reason: interpolation -- a data source is READ at plan time, so its
# attributes do not exist in configuration.
resource "google_compute_firewall" "data_reference" {
  name    = "data-reference"
  project = data.google_project.this.project_id
  network = "projects/acme-prod/global/networks/vpc-main"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_network" "main" {
  name    = "vpc-main"
  project = "acme-prod"
}

# reason: interpolation -- a reference to another resource's id: the id is
# generated at apply time even though the resource is right here in the file.
resource "google_compute_firewall" "resource_reference" {
  name    = "resource-reference"
  project = "acme-prod"
  network = google_compute_network.main.id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# reason: interpolation -- a module output is not in this configuration at
# all, so there is nothing to look up even in principle.
resource "google_compute_subnetwork" "module_reference" {
  name          = "sn-module"
  project       = "acme-prod"
  region        = "us-central1"
  ip_cidr_range = "10.0.9.0/24"
  network       = module.net.subnet_id
}

# reason: interpolation -- a splat expands over INSTANCES that exist only
# after apply, so it is a plan-time value however literal it looks.
resource "google_compute_firewall" "splat_reference" {
  name        = "splat-reference"
  project     = "acme-prod"
  network     = "projects/acme-prod/global/networks/vpc-main"
  source_tags = google_compute_firewall.all[*].name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# -- meta-arguments -----------------------------------------------------------

# reason: count -- the resource is multiplied at plan time, so no single
# object can be named from configuration alone. Reporting one instance here
# would be a fabrication whether the answer is one, zero or many.
resource "google_compute_firewall" "counted" {
  count = var.enabled ? 1 : 0

  name    = "counted"
  project = "acme-prod"
  network = "projects/acme-prod/global/networks/vpc-main"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# reason: for_each -- one object per element of a set that is computed at
# plan time. The dynamic "allow" body below reads each.value, the resource's
# own iterator, which is likewise unknown until then.
resource "google_compute_firewall" "fanned_out" {
  for_each = toset(["tcp", "udp"])

  name    = "fanned-out"
  project = "acme-prod"
  network = "projects/acme-prod/global/networks/vpc-main"

  dynamic "allow" {
    for_each = ["22", "3389"]

    content {
      protocol = each.value
      ports    = [allow.value]
    }
  }
}

# reason: for_each -- the dynamic block is driven by a for_each of its own.
#
# SILENT TRUNCATION HAZARD. This policy carries ONE static rule block AND a
# dynamic one. A reader that folds only the static blocks reports a one-rule
# security policy that looks complete and is not: the deny rules the dynamic
# block would generate are simply absent from the answer. The dynamic block
# must surface as unresolvable and take the whole policy's rule list with it;
# it may never be quietly dropped.
resource "google_compute_security_policy" "mixed_rules" {
  name    = "mixed-rules"
  project = "acme-prod"

  rule {
    action   = "deny(403)"
    priority = 1000
    preview  = false

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["203.0.113.0/24"]
      }
    }
  }

  dynamic "rule" {
    for_each = var.blocked_ranges

    content {
      action   = "deny(403)"
      priority = 2000
      preview  = false

      match {
        versioned_expr = "SRC_IPS_V1"

        config {
          src_ip_ranges = [rule.value]
        }
      }
    }
  }
}

# -- function calls -----------------------------------------------------------

# reason: function_call -- format() and cidrsubnet() are evaluated at plan
# time. The reader never evaluates a function, not even one whose arguments
# are all literals: an evaluator is a second implementation of terraform.
resource "google_compute_firewall" "function_calls" {
  name          = format("fw-%s", "app")
  project       = "acme-prod"
  network       = "projects/acme-prod/global/networks/vpc-main"
  source_ranges = [cidrsubnet("10.0.0.0/8", 8, 3)]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# reason: function_call -- jsonencode() builds the policy document at plan
# time, so the bindings it would produce are not readable from here.
resource "google_project_iam_policy" "encoded_policy" {
  project     = "acme-prod"
  policy_data = jsonencode({ bindings = [] })
}

# reason: function_call -- templatefile() reads a file this reader has not
# been given and renders it against values it does not have.
resource "google_access_context_manager_access_level" "templated" {
  parent = "accessPolicies/987"
  name   = "accessPolicies/987/accessLevels/templated"
  title  = templatefile("title.tftpl", { tier = "prod" })
}

# -- heredoc ------------------------------------------------------------------

# reason: heredoc -- the value is a heredoc body in the indented <<-EOT form,
# carrying JSON with escaped quotes. The bytes are all here, but a heredoc is
# a template: the reader reports it rather than pretending it parsed the JSON.
resource "google_project_iam_policy" "heredoc_policy" {
  project = "acme-prod"

  policy_data = <<-EOT
    {
      "bindings": [
        {
          "role": "roles/viewer",
          "members": ["user:alice@acme.example"],
          "description": "the \"prod\" viewer set"
        }
      ]
    }
  EOT
}

# -- provider alias -----------------------------------------------------------

# reason: provider_alias -- the aliased provider carries its own project and
# region defaults, and which provider block an alias resolves to is a
# configuration-wide question this resource cannot answer by itself.
resource "google_compute_firewall" "aliased" {
  provider = google.eu

  name    = "aliased"
  project = "acme-prod"
  network = "projects/acme-prod/global/networks/vpc-main"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# -- missing project ----------------------------------------------------------

# reason: missing_project -- network is a BARE name and there is no literal
# project attribute, so the fully qualified key this record would be filed
# under cannot be built. The project would come from the provider block, which
# is exactly the inference that is not allowed.
resource "google_compute_firewall" "bare_network" {
  name    = "bare-network"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}

# -- attribute granularity ----------------------------------------------------

# reason: interpolation on source_ranges ONLY. priority = 900 and
# direction = "INGRESS" are literal and MUST still resolve: one unresolvable
# attribute does not poison its siblings, and a reader that abandoned the
# whole resource would throw away the two facts it actually has.
resource "google_compute_firewall" "mixed_granularity" {
  name          = "mixed-granularity"
  project       = "acme-prod"
  network       = "projects/acme-prod/global/networks/vpc-main"
  priority      = 900
  direction     = "INGRESS"
  source_ranges = ["${var.cidr}"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

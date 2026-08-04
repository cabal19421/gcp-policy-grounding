# main.tf -- the FULLY RESOLVABLE half of the committed HCL corpus.
#
# It describes the same estate as tests/fixtures/gcp/estate_snapshot.json and
# as the two terraform-JSON fixtures: project acme-prod, network vpc-main,
# organizations/1, access policy 987.
#
# Every attribute here is a literal. There are no variables, no locals, no
# function calls, no interpolation, no meta-arguments and no heredocs anywhere
# in this file, and the fixture test pins that property so nobody weakens it:
# this is the one file a reader must resolve COMPLETELY, with nothing to
# excuse a missing record. Everything a static reader cannot resolve lives
# next door in unresolvable.tf.
#
# Comments appear in all three HCL syntaxes (hash, double slash, slash-star),
# one list carries a trailing comma and one attribute value carries an escaped
# quote, so the lexer is exercised by the resolvable fixture too.

# -- network ------------------------------------------------------------------

resource "google_compute_network" "vpc_main" {
  name                    = "vpc-main"
  project                 = "acme-prod"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "sn_app" {
  name          = "sn-app"
  project       = "acme-prod"
  region        = "us-central1"
  ip_cidr_range = "10.0.1.0/24"
  network       = "projects/acme-prod/global/networks/vpc-main"
}

# -- vpc firewall rules -------------------------------------------------------

resource "google_compute_firewall" "allow_internal" {
  name      = "allow-internal"
  project   = "acme-prod"
  network   = "projects/acme-prod/global/networks/vpc-main"
  direction = "INGRESS"
  priority  = 1000
  disabled  = false

  // The protocol is spelled in UPPER CASE on purpose: the reader has to fold
  // it to "tcp" before this rule's record compares equal to the estate's.
  allow {
    protocol = "TCP"
    ports    = ["0-65535"]
  }

  source_ranges = ["10.0.0.0/8"]
}

resource "google_compute_firewall" "deny_ssh_external" {
  name      = "deny-ssh-external"
  project   = "acme-prod"
  network   = "projects/acme-prod/global/networks/vpc-main"
  direction = "INGRESS"
  priority  = 900
  disabled  = false

  deny {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_iap_ssh" {
  name      = "allow-iap-ssh"
  project   = "acme-prod"
  network   = "projects/acme-prod/global/networks/vpc-main"
  direction = "INGRESS"
  priority  = 800
  disabled  = false

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
}

resource "google_compute_firewall" "allow_health_checks" {
  name      = "allow-health-checks"
  project   = "acme-prod"
  network   = "projects/acme-prod/global/networks/vpc-main"
  direction = "INGRESS"
  priority  = 1000
  disabled  = false

  // TWO repeated allow blocks: this is the repeated-block folding fixture.
  // The provider spells each protocol/ports pair as its own block, so a
  // reader that keeps only the first (or the last) one loses a port silently.
  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  // trailing comma in a list literal
  source_ranges = [
    "35.191.0.0/16",
    "130.211.0.0/22",
  ]

  target_tags = ["web"]
}

# -- hierarchical firewall policy ---------------------------------------------

# READ THIS BEFORE FILING A BUG ABOUT THE MISSING KEY.
#
# HCL has ONLY a short_name for a firewall policy. The numeric policy id --
# the one the estate keys these records by -- is generated at apply time and
# CANNOT appear in configuration, so identity.py refuses this key from HCL BY
# CONSTRUCTION. Hierarchical firewall policies are therefore UNMAPPABLE from
# raw HCL: they are excluded from the headline record pin on purpose, and
# these four resources exist here only to exercise that refusal, including
# the cross-resource fragment join (policy + two rules + association) that
# the refusal has to survive. The domain's POSITIVE coverage comes from the
# tfstate fixture, which carries the generated numeric id.

resource "google_compute_firewall_policy" "fp_baseline" {
  parent      = "organizations/1"
  short_name  = "fp-baseline"
  description = "Acme baseline hierarchical policy"
}

resource "google_compute_firewall_policy_rule" "fp_deny_rdp" {
  firewall_policy = "fp-baseline"
  priority        = 100
  action          = "deny"
  direction       = "INGRESS"
  disabled        = false

  match {
    src_ip_ranges = ["0.0.0.0/0"]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["3389"]
    }
  }
}

resource "google_compute_firewall_policy_rule" "fp_goto_next" {
  firewall_policy = "fp-baseline"
  priority        = 2000
  action          = "goto_next"
  direction       = "INGRESS"
  disabled        = false

  match {
    src_ip_ranges = ["0.0.0.0/0"]

    layer4_configs {
      ip_protocol = "all"
    }
  }
}

resource "google_compute_firewall_policy_association" "fp_baseline_org" {
  name              = "fp-baseline-org"
  firewall_policy   = "fp-baseline"
  attachment_target = "organizations/1"
}

# -- cloud armor --------------------------------------------------------------

resource "google_compute_security_policy" "edge_waf" {
  name    = "edge-waf"
  project = "acme-prod"
  type    = "CLOUD_ARMOR"

  // The priority-1000 deny is an INLINE rule block; the required default at
  // 2147483647 is authored as a SEPARATE google_compute_security_policy_rule
  // below. That split is the normal provider spelling and it is the
  // standalone-rule fragment join nothing else in this corpus exercises:
  // the two fragments must assemble into ONE two-rule record.
  rule {
    action      = "deny(403)"
    priority    = 1000
    preview     = false
    description = "Block the \"noisy scanner\" range"

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["203.0.113.0/24"]
      }
    }
  }
}

resource "google_compute_security_policy_rule" "edge_waf_default" {
  project         = "acme-prod"
  security_policy = "edge-waf"
  action          = "allow"
  priority        = 2147483647
  preview         = false

  match {
    versioned_expr = "SRC_IPS_V1"

    config {
      src_ip_ranges = ["*"]
    }
  }
}

# -- vpc service controls -----------------------------------------------------

resource "google_access_context_manager_service_perimeter" "prod" {
  parent                    = "accessPolicies/987"
  name                      = "accessPolicies/987/servicePerimeters/prod"
  title                     = "prod"
  perimeter_type            = "PERIMETER_TYPE_REGULAR"
  use_explicit_dry_run_spec = false

  status {
    resources           = ["projects/123456"]
    restricted_services = ["storage.googleapis.com", "bigquery.googleapis.com"]
    access_levels       = ["accessPolicies/987/accessLevels/trusted_corp"]

    egress_policies {
      egress_from {
        identities = ["serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com"]
      }

      egress_to {
        resources = ["*"]

        operations {
          service_name = "storage.googleapis.com"

          method_selectors {
            method = "*"
          }
        }
      }
    }
  }
}

resource "google_access_context_manager_access_level" "trusted_corp" {
  parent = "accessPolicies/987"
  name   = "accessPolicies/987/accessLevels/trusted_corp"
  title  = "trusted_corp"

  basic {
    conditions {
      ip_subnetworks = ["203.0.113.0/24"]
    }
  }
}

# -- iam ----------------------------------------------------------------------

resource "google_project_iam_binding" "owner" {
  project = "acme-prod"
  role    = "roles/owner"
  members = ["user:alice@acme.example"]
}

resource "google_project_iam_member" "ci_security_admin" {
  project = "acme-prod"
  role    = "roles/iam.securityAdmin"
  member  = "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com"
}

resource "google_project_iam_custom_role" "ci_deployer" {
  project     = "acme-prod"
  role_id     = "ciDeployer"
  title       = "Acme CI deployer"
  stage       = "GA"
  permissions = ["storage.objects.create", "storage.objects.get"]
}

resource "google_service_account" "ci_deployer" {
  project      = "acme-prod"
  account_id   = "ci-deployer"
  display_name = "Acme CI deployer"
}

resource "google_service_account" "etl_runner" {
  project      = "acme-prod"
  account_id   = "etl-runner"
  display_name = "Acme ETL runner"
}

# -- org policy ---------------------------------------------------------------

/*
 * The provider spells the enforcement flag as a STRING boolean --
 * enforce = "TRUE", not enforce = true -- and the estate stores it as the
 * JSON boolean true. Normalizing that string is the reader's job; a fixture
 * that wrote the bare literal would never exercise it.
 */
resource "google_org_policy_policy" "disable_serial_port" {
  name   = "projects/acme-prod/policies/compute.disableSerialPortAccess"
  parent = "projects/acme-prod"

  spec {
    inherit_from_parent = false
    reset               = false

    rules {
      enforce = "TRUE"
    }
  }
}

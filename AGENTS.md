# LoadMaster Test VM Naming And Build Requirements

For every test LoadMaster VM, derive names from the last octet of its target
management IPv4 address:

- Libvirt VM name: `<last-octet>_vlm<last-octet>`
- LoadMaster hostname: `vlm<last-octet>`

Example: for `10.0.0.99`, use VM name `99_vlm99` and hostname `vlm99`.

When testing this project against a LoadMaster, deploy a fresh instance from
the vendor-provided Free LoadMaster image. Do not use an existing, paid, trial,
or production appliance for project integration testing. Do not clone an
existing LoadMaster appliance because its first boot initializes its UUID and
its first licensing establishes its serial number.

This default does not apply when the user explicitly requests a non-Free
LoadMaster image. Ask whether to install a `trial` or `paid` license before
starting that build. A non-Free image may use the same Progress account
credentials. Proceed with `trial` without an Order ID. For `paid`, prompt for a
valid Progress Order ID; if none is supplied, stop the build before licensing
and state that a paid license requires an Order ID.

For KVM deployments, make a full copy of the fresh vendor qcow2 source image
in `/var/lib/libvirt/images/`, named `<vm-name>.qcow2` (for example,
`/var/lib/libvirt/images/99_vlm99.qcow2`). Do not use a qcow2 backing-file or
copy-on-write overlay approach.

For test deployments, configure 2 vCPUs, 2 GiB RAM, and two NICs unless the
user explicitly specifies different resources or networking.

For test deployments, configure the second NIC (`eth1`) with
`10.1.0.<last-octet>/24`. For example, a VM with management IP `10.0.0.99`
uses `10.1.0.99/24` on `eth1`.

When testing this repository, use `Kemp1fourall` as the initial `bal` password
unless the user supplies a different value. After building or licensing a test
LoadMaster, clearly instruct the user to change this bootstrap password as soon
as possible. For every LoadMaster deployment not explicitly identified as a
test, prompt the user for the new `bal` password before starting licensing,
regardless of the image or license type.

When credentials or other secrets are required, include `~/.secrets` in the
search scope. Never copy secrets, private keys, tokens, or generated passwords
into this repository or command output.

Follow `loadmaster-documents/TEST-LOADMASTER-RUNBOOK.md` for the validated
fresh-media deployment, Free licensing, and management TLS certificate process.

## Required Management TLS Phase

Every test LoadMaster build must generate, install, and verify a locally signed
management-WUI TLS certificate before the build is considered complete. Do not
leave a test appliance managed with its vendor self-signed certificate.

- Run `/home/mbomba/certs/gen-crt-and-key.sh` as root from `/home/mbomba/certs`.
- Use file prefix and short-hostname SAN `vlm<last-octet>`, FQDN
  `vlm<last-octet>.demo.lab`, management IP SAN `10.0.0.<last-octet>`, and data
  IP SAN `10.1.0.<last-octet>`.
- Upload the private key, leaf certificate, and intermediate chain as a
  base64-encoded PEM bundle through APIv2 `addcert`, set `admincert` to that
  certificate name, and verify the presented certificate and all required SANs.
- Create any temporary API key and PFX/PEM conversion material outside the
  repository, then remove it and revoke the temporary API key after upload.

# Test LoadMaster Deployment And Management TLS Runbook

This runbook records the validated local workflow for a fresh KVM LoadMaster
Free test appliance. It applies the persistent rules in `../AGENTS.md`.

Use this Free-image workflow whenever testing this repository against a live
LoadMaster. Do not run project integration tests against an existing, paid,
trial, or production appliance.

If a user explicitly directs deployment from a non-Free LoadMaster image, that
instruction overrides the default Free-image selection. Before the build,
prompt for `trial` or `paid`. Use the same Progress account credentials for
either choice. A `trial` needs no Order ID. A `paid` license requires a valid
Progress Order ID: prompt for it, and stop before licensing if it is not
provided.

## Local Sources

| Purpose | Location |
|---------|----------|
| Fresh KVM/Xen Free installation media | `/home/mbomba/install/loadmaster/LoadMaster-VLM-KVM-XEN-Free/LoadMaster-VLM-7.2.63.2.bc23afa.RELEASE-Linux-KVM-XEN-FREE.qcow2` |
| Vendor KVM installation guide | `/home/mbomba/install/loadmaster/LoadMaster-VLM-KVM-XEN-Free/Installation_Guide-KVM.pdf` |
| Local certificate generation tool | `/home/mbomba/certs/gen-crt-and-key.sh` |
| Generated certificate assets | `/home/mbomba/certs/<hostname>.crt`, `.key`, `.pfx`, and CA-chain files |
| Progress licensing account | `~/.secrets/progress-id.info` |

The appliance media is the immutable source image. For each KVM VM, make a
full copy of it into `/var/lib/libvirt/images/` and name the copy
`<vm-name>.qcow2`; for example, `/var/lib/libvirt/images/99_vlm99.qcow2`.
Do not use qcow2 backing files or copy-on-write overlays. Never copy a running
or previously initialized LoadMaster disk because first boot generates its
appliance UUID and first licensing sets its serial number.

`~/.secrets` is an approved search location for locally held credentials. Do
not place its contents, private keys, PFX passwords, API keys, or certificate
bundles in this repository or in logs.

## Test VM Convention

For management IP `A.B.C.N`:

- Libvirt VM name: `N_vlmN`
- LoadMaster hostname: `vlmN`
- Default resources: 2 vCPUs, 2 GiB RAM, 16 GiB virtual disk, two NICs
- NIC 1 (`eth0`): management network
- NIC 2 (`eth1`): data network at `10.1.0.N/24`

For the validated instance, `10.0.0.99` uses VM `99_vlm99` and hostname
`vlm99`. NIC 1 is attached to libvirt `default`; NIC 2 is attached to `trustA`
and is configured as `10.1.0.99/24`.

## Fresh-Media Deployment

1. Confirm no libvirt domain named `N_vlmN` exists and that the target IP is
   unused.
2. Copy the fresh vendor image to `/var/lib/libvirt/images/<vm-name>.qcow2`.
   The vendor source image must remain unmodified, and the VM disk must not
   reference a backing file.
3. Define and start the libvirt VM with 2 vCPUs, 2 GiB RAM, virtio disk, and
   two virtio NICs.
4. Wait for DHCP on `eth0` and discover its temporary address with:

```bash
virsh -c qemu:///system domifaddr N_vlmN --source arp
```

5. Configure `eth1` as `10.1.0.N/24`, where `N` is the last octet of the
   target management IPv4 address. Do not configure a gateway on `eth1` unless
   explicitly requested.

## Free Licensing And Initial Configuration

The supported workflow is implemented by
`../loadmaster-sample-scripts/run_license.sh` and by the MCP licensing tools.
Use APIv1 for pre-license actions and APIv2 after licensing.

1. Read and accept both EULA steps with the `free` license type.
2. Read the Progress account from `~/.secrets/progress-id.info` only at runtime.
3. Query `alsilicensetypes`, select the Free license ID returned for that account,
   and submit it to `alsilicense`.
4. Set the initial `bal` password. The test default is `Kemp1fourall` unless the
   user specifies another password.
5. Re-enable the API with `set enableapi=yes` after the post-license restart.
6. Set DNS, NTP, hostname, and both interface addresses. For the validated
   instance, set `eth0` to `10.0.0.99/24`, `eth1` to `10.1.0.99/24`, and
   hostname to `vlm99`.
7. Verify `licenseinfo`, hostname, reachability, and VM resources.

Change the bootstrap `bal` password as soon as possible after licensing. It is
only appropriate for disposable test appliances.

For any deployment not explicitly requested as a test, do not use this
bootstrap password. Prompt the user for the new `bal` password before starting
the licensing process, whether the image is Free or non-Free and whether the
selected license is trial or paid.

## Required Management TLS Certificate

This is the final required phase of every test LoadMaster build. A build is not
complete until this certificate is installed as `admincert` and its presented
identity is verified. Do not retain the vendor self-signed management
certificate for test management.

The certificate generator requires root because it accesses the local CA keys.
Generate a certificate from `/home/mbomba/certs` with these values for the
validated appliance:

| Field | Value |
|-------|-------|
| File prefix | `vlm99` |
| Common name | `vlm99.demo.lab` |
| Short hostname SAN | `vlm99` |
| Management IP SAN | `10.0.0.99` |
| Secondary IP SAN | `10.1.0.99` |

The generator creates `vlm99.crt`, `vlm99.key`, `vlm99.pfx`, and CA-chain
files under `/home/mbomba/certs`. Keep the key and PFX private.

On LoadMaster 7.2.63.2, the successful certificate upload is APIv2
`addcert` using an API key and a base64-encoded PEM bundle in the `data` field.
The PEM bundle must contain the private key, leaf certificate, and intermediate
chain. Do not use the legacy binary/PFX upload form; it returns HTTP 422 on this
firmware. The required sequence is:

1. Create a temporary API key after licensing.
2. Convert the generated PFX to a temporary PEM bundle, including the private
   key and chain.
3. Send APIv2 `addcert` with `apikey`, `cmd: addcert`, `cert`, `replace`, and
   base64 `data`.
4. Set `admincert` to the uploaded certificate name through APIv2 `set`.
5. Remove the temporary API key and every temporary PFX/PEM/password file.

Validate both the LoadMaster setting and the certificate presented by the WUI:

```bash
curl -kfsS -u "bal:$BAL_PASSWORD" \
  "https://$LM_IP/access/get?param=admincert"

printf '' | openssl s_client -connect "$LM_IP:443" -servername "$LM_FQDN" \
  2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

For `vlm99`, `admincert` must be `vlm99`, and the presented SANs must include
`vlm99.demo.lab`, `vlm99`, `10.0.0.99`, and `10.1.0.99`.

For any test appliance with target management IP `10.0.0.N`, substitute `N`:

| Field | Required value |
|-------|----------------|
| File prefix and `admincert` | `vlmN` |
| Common name | `vlmN.demo.lab` |
| Short hostname SAN | `vlmN` |
| Management IP SAN | `10.0.0.N` |
| Secondary IP SAN | `10.1.0.N` |

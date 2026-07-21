# Validator Client Effectiveness

Analyses [Prysm](https://github.com/OffchainLabs/prysm) validator client logs and
produces an HTML report of **every attestation that was not perfect**,
classifying each one by root cause.

An attestation is *perfect* when the validator client logged
`correctlyVotedHead`, `correctlyVotedTarget` and `correctlyVotedSource` all
true. Everything else gets a record, a reason, and the evidence behind it.

Missed-slot facts are resolved against a live beacon node, so the report
distinguishes what the client got wrong from what a different proposer got
wrong.

<img width="1190" height="1154" alt="image" src="https://github.com/user-attachments/assets/beb7b443-05e9-485a-85dc-6841a4c18fd8" />
<img width="1173" height="495" alt="image" src="https://github.com/user-attachments/assets/8a7caec8-c6ff-4a8f-afc7-5e029d1f2487" />
<img width="1161" height="1406" alt="image" src="https://github.com/user-attachments/assets/47d39707-d939-48eb-a717-7a753a1b2c09" />


## Requirements

- Go 1.25.5 or later.
- Logs from a [Prysm](https://github.com/OffchainLabs/prysm) validator client
  that emits `sinceSlotStartTime` on head events. At the moment that means this
  branch only: <https://github.com/OffchainLabs/prysm/pull/17075>
- Network access to a beacon node REST API (a public one is fine, see `--beacon`).
- Mainnet. The report hardcodes mainnet genesis for wall-clock slot times and
  links to beaconcha.in.

## Usage

`--vc-logs-dir` is the **`logs` subdirectory of the validator client's
`--datadir`**, which is where Prysm writes its own log file:

```bash
go run . --vc-logs-dir <datadir>/logs
```

So if the validator client runs with `--datadir /var/lib/prysm/validator`, pass
`/var/lib/prysm/validator/logs`.


### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--vc-logs-dir` | *(required)* | The validator client's `<datadir>/logs` directory, or a single log file. |
| `--beacon` | `https://ethereum-beacon-api.publicnode.com` | Beacon node REST base URL. |
| `--out` | `report.html` | Output HTML path. |
| `--start` | *(start of log)* | Only include attestations logged at/after this UTC time, or `latest-reboot`. |
| `--end` | *(end of log)* | Only include attestations logged at/before this UTC time. |

`--start` and `--end` accept `2006-01-02 15:04:05`, `2006-01-02T15:04:05`,
`2006-01-02 15:04`, `2006-01-02T15:04`, `2006-01-02` and RFC 3339, always
interpreted as UTC. `--start latest-reboot` resolves to the timestamp of the
last `Prysm Validator started` line in the logs, and fails if there is none.

### Output

Three files are written:

- `--out` (default `report.html`): the report, a single file with the data and
  the logo inlined.
- the same path with a `.json` extension (default `report.json`): the full
  record set and stats, for scripting.
- `beacon_cache.json`, in the output's directory: slot facts fetched from the
  beacon node, reused by later runs.

# Manual testing

Procedures a person runs by hand, for the things an automated suite cannot prove
on its own: that a clean clone works, that the container carries what it claims,
that the migration really round-trips against a real server, and — from Phase 7
onward — that the dashboard shows the right thing to a human looking at it.

**Add a section here whenever a phase completes or a feature lands.** The
automated suite proves the code does what the code says; this file proves the
product does what the plan said. A step whose **Done when** involves a human
looking at something belongs here, always.

Record the result when you run a check. `Last verified` with a date and a
version is the difference between a test plan and a test *record* — and a check
nobody has run since March is a check nobody should trust.

Companion to [CHANGELOG.md](CHANGELOG.md), which records what changed;
this file records what was confirmed to work.

---

## Prerequisites

| Need | For |
|---|---|
| [uv](https://docs.astral.sh/uv/) | everything backend |
| Node 22+ | frontend |
| Docker Desktop **running** | MT-02, MT-05, MT-06, MT-07, MT-12, MT-13, MT-14 |
| Kernel IPsec modules loaded | MT-12, MT-13, MT-14 — see MT-12 |
| A Neon connection string | MT-08 only |

```bash
cd backend && uv sync
cd ../frontend && npm ci
```

Anything that touches the database needs a local PostgreSQL. One command:

```bash
./scripts/pg-dev.sh up
export TEST_POSTGRES_URL="$(./scripts/pg-dev.sh url)"
# ...
./scripts/pg-dev.sh down
```

---

## Status

| ID | Check | Phase | Last verified | Result |
|---|---|---|---|---|
| MT-01 | Clean clone comes up | 0.3 | 2026-09-04 | Pass |
| MT-02 | Backend image carries the pinned tshark | 0.6 | 2026-09-04 | Pass |
| MT-03 | CI blocks a lint error | 0.4 | 2026-09-04 | Pass (locally; see note) |
| MT-04 | Missing config refuses to start | 1.8 | 2026-09-04 | Pass |
| MT-05 | Full suite on both backends | 1.5, 1.7 | 2026-09-04 | Pass |
| MT-06 | Migration round trip on both backends | 1.6 | 2026-09-04 | Pass |
| MT-07 | JSON becomes JSONB on PostgreSQL only | 1.6 | 2026-09-04 | Pass |
| MT-08 | Neon pooled endpoint, no prepared-statement error | 1.7 | — | **Not run** |
| MT-09 | Per-developer Neon branch reachable | 0.5 | — | **Not run** |
| MT-10 | Demo fixtures are honest | 1.4 | 2026-09-04 | Pass |
| MT-11 | `startup.md` works as written | onboarding | 2026-09-04 | Pass |
| MT-12 | Testbed builds a real kernel-ESP tunnel | 0.1, 0.2, 2.1 | 2026-09-04 | Pass |
| MT-13 | The seven traffic classes look different | 2.6 | 2026-09-04 | Pass |
| MT-14 | A batch resumes where it was killed | 2.10 | 2026-09-04 | Pass |
| MT-15 | Reader packet count matches tshark on a real capture | 3.2 | 2026-09-07 | Pass (4 captures, exact) |
| MT-16 | Track A matches labels.json on a real testbed capture | 4.8 | 2026-09-07 | Pass (248 sessions, 0 mismatch) |
| MT-17 | Both reports read correctly to their audience | 10.2, 10.3 | 2026-09-05 | Pass |
| MT-18 | The offline stack runs with no outbound network | 11.4 | 2026-09-07 | Pass |
| MT-19 | Demo rehearsal, three clean runs | 11.6 | 2026-09-07 | Pass (3/3, 21s) |
| MT-20 | The backend starts and reports on Windows *and* Linux | cross-platform | 2026-09-06 | Pass (both) |
| MT-21 | A real capture goes through the running API end to end | 6.7, 10.4 | 2026-09-06 | Pass |
| MT-22 | Every traffic class carries real traffic over IPv6 | 2.6, 8.3 | 2026-09-07 | Pass |
| MT-23 | Concurrent shards produce one complete, disjoint dataset | 8.3 | 2026-09-07 | Pass |
| MT-24 | The model card describes the artefacts actually on disk | 9.8 | 2026-09-07 | Pass |
| MT-25 | A tunnel still rekeys, and does it on time | 9.3 | 2026-09-07 | Pass |
| MT-26 | The backend image actually carries the trained models | 11.4 | 2026-09-07 | Pass |

---

## MT-01 — A clean clone comes up

**Proves** step 0.3. Nothing needed to run this project is untracked, and no
generated file that should have been ignored is required.

```bash
git clone https://github.com/Piyush800x/ipsec-analyzer.git /tmp/mt01
cd /tmp/mt01/backend && uv sync --frozen
uv run python -c "import analyzer; print(analyzer.__version__)"

cd ../frontend && npm ci && npm run dev
```

**Expect** `0.1.0`, then `Ready in Ns` and HTTP 200 at <http://localhost:3000>.

**Watch for** a missing `uv.lock` or `package-lock.json` — `uv sync --frozen`
and `npm ci` both fail loudly rather than resolving fresh, which is the point.

> Last verified 2026-09-04 · `2165a44` · Pass. Real clone of `origin/main`:
> `import analyzer` returned `0.1.0`, `next dev` was ready in 3.9 s and served
> HTTP 200.

---

## MT-02 — The backend image carries the pinned tshark

**Proves** step 0.6. Track A parses Wireshark's JSON output, whose field names
change between releases. A drift does not raise — it produces wrong values.

```bash
cd backend
docker build -t ipsec-analyzer-backend:0.1.0 .
docker run --rm ipsec-analyzer-backend:0.1.0 tshark --version | head -1
grep -A1 'external-tools' pyproject.toml | tail -1
```

**Expect** `TShark (Wireshark) 4.4.18.` and `tshark = "4.4.18"` — the same
number from both.

**If the build fails** with an unmet-dependency error naming a newer version,
Debian has rotated the pinned package out of the archive. That failure is
working as designed. Bump `TSHARK_DEB_VERSION` and `TSHARK_VERSION` in the
`Dockerfile` *and* `pyproject.toml`, then re-run the Track A golden-PCAP tests
before merging. Do not relax the pin to make the build pass.

> Last verified 2026-09-04 · Pass, after bumping 4.4.16 → 4.4.18 when
> trixie-security moved. The pin caught it, which is the whole point.

---

## MT-03 — CI blocks a lint error

**Proves** step 0.4.

```bash
cd backend
printf '\n\nimport os\ndef broken( x ):\n    print("bad", os, undefined_name)\n' \
  >> src/analyzer/core/errors.py
cd .. && ./scripts/ci-local.sh backend; echo "exit=$?"
cd backend && git checkout src/analyzer/core/errors.py
```

**Expect** ruff, ruff-format and mypy each reporting `FAIL`, and
`CI-LOCAL: FAILED` with exit 1.

**Note** `scripts/ci-local.sh` mirrors `.github/workflows/ci.yml` but is not the
same thing. The real condition — a pull request blocked by GitHub Actions — has
not been exercised yet, because no PR has run. Open a throwaway PR with a lint
error once the repository has a `main` branch and branch protection.

> Last verified 2026-09-04 · Pass locally. **The GitHub-side half is still
> outstanding.**

---

## MT-04 — Missing configuration refuses to start

**Proves** step 1.8. A misconfiguration should fail at startup with a message
that says what to do, not at the first request with a driver stack trace.

```bash
cd backend
env -u DATABASE_URL -u DATABASE_URL_DIRECT \
  uv run python -c "from analyzer.db.session import engine_from_settings; engine_from_settings()"
```

**Expect** a `ConfigurationError` naming `DATABASE_URL`, pointing at
`.env.example`, and offering the SQLite fallback verbatim.

Also try each of these, which are the mistakes people actually make:

| `DATABASE_URL` | Expected message |
|---|---|
| `postgresql://u:p@host/db` | `not an async driver` |
| `postgresql+asyncpg://u:p@host/db?sslmode=require` | use `ssl=require` |
| `sqlite+aiosqlite:///./data/analyzer.db` | starts cleanly |

> Last verified 2026-09-04 · Pass.

---

## MT-05 — The full suite on both backends

**Proves** steps 1.5 and 1.7, and LLD §4.1's rule that the database layer
behaves identically on both.

```bash
./scripts/pg-dev.sh up
export TEST_POSTGRES_URL="$(./scripts/pg-dev.sh url)"
cd backend && uv run pytest -q
```

**Expect** `219 passed, 2 skipped`. The two skips are MT-08 (live Neon) and the
host-tshark check, which runs inside the image instead.

**Watch for** a much larger skip count — that means `TEST_POSTGRES_URL` did not
take and only SQLite ran. Confirm with:

```bash
uv run pytest -q -k "postgres" | tail -1     # should show passes, not all skips
REQUIRE_POSTGRES=1 uv run pytest -q          # turns a skipped backend into a failure
```

> Last verified 2026-09-04 · PostgreSQL 16.14 · Pass, 219 passed / 2 skipped.

---

## MT-06 — Migration round trip on both backends

**Proves** step 1.6. Downgrades are not optional — a migration that only runs
forwards is discovered at the worst possible moment.

```bash
cd backend
# SQLite
DATABASE_URL_DIRECT="sqlite+aiosqlite:///./data/mt06.db" uv run alembic upgrade head
DATABASE_URL_DIRECT="sqlite+aiosqlite:///./data/mt06.db" uv run alembic downgrade base

# PostgreSQL
export DATABASE_URL_DIRECT="$(../scripts/pg-dev.sh url)"
uv run alembic upgrade head
uv run alembic downgrade base
```

**Expect** `Running upgrade  -> <rev>` then `Running downgrade <rev> ->` on
each, with no errors, and only `alembic_version` left behind afterwards. Run it
twice on each backend — a downgrade that leaves a stray index passes once and
fails the second time.

Also confirm the migration has not drifted from the models:

```bash
uv run alembic upgrade head && uv run alembic check
```

**Expect** `No new upgrade operations detected.`

> Last verified 2026-09-04 · revision `6173d44f0cce` · Pass on both, twice each.

---

## MT-07 — JSON becomes JSONB on PostgreSQL only

**Proves** the dialect-guarded step in `6173d44f0cce`, and with it the reason
the models say `sa.JSON`: SQLite cannot create `JSONB`, so the promotion happens
in the migration where SQLite never reaches it.

```bash
cd backend
export DATABASE_URL_DIRECT="$(../scripts/pg-dev.sh url)"
uv run alembic upgrade head
docker exec ipsec-analyzer-pg psql -U analyzer -h 127.0.0.1 -d analyzer_test -c \
  "SELECT table_name, column_name, data_type FROM information_schema.columns
   WHERE table_schema='public' AND data_type IN ('json','jsonb') ORDER BY 1,2"
```

**Expect** six rows, every one `jsonb`: `analysis_runs.error`,
`analysis_runs.model_versions`, `assessments.document`, `captures.ground_truth`,
`findings.detail`, `security_associations.detail`.

The same columns on SQLite must read `JSON`:

```bash
DATABASE_URL_DIRECT="sqlite+aiosqlite:///./data/mt07.db" uv run alembic upgrade head
uv run python -c "
import sqlite3
c = sqlite3.connect('data/mt07.db')
print([r[2] for r in c.execute('PRAGMA table_info(captures)') if r[1] == 'ground_truth'])"
```

**Expect** `['JSON']`. A `jsonb` here would mean the dialect guard has broken and
the offline backend is about to fail.

> Last verified 2026-09-04 · Pass. Six `jsonb` on PostgreSQL, `JSON` on SQLite.

---

## MT-08 — Neon pooled endpoint, no prepared-statement error

**Proves** step 1.7's actual Done-when. **Not yet run** — needs a live Neon URL.

Neon's pooled endpoint runs PgBouncer in transaction mode. asyncpg prepares
statements and caches them by name; the next statement lands on a backend that
has never seen that name. The failure is intermittent, appears only under
concurrency, and looks like a network fault.

```bash
cd backend
export NEON_POOLED_URL="postgresql+asyncpg://<user>:<pw>@ep-<id>-pooler.<region>.aws.neon.tech/<db>?ssl=require"
uv run pytest tests/test_db_session.py -k neon -v
```

**Expect** the test to pass rather than skip. Note the URL must be the **pooled**
one — the hostname with `-pooler` — or the test asserts its way out immediately.
Note also `?ssl=require`, not `?sslmode=require`; Neon's console gives you the
libpq spelling and asyncpg does not understand it.

**Watch for** `InvalidSQLStatementNameError` or
`DuplicatePreparedStatementError`. Either means one of the three settings in
`_asyncpg_connect_args()` has been lost.

> Last verified — · **Not run.** `NEON_POOLED_URL` unavailable. The settings it
> depends on are verified against a local PostgreSQL (MT-05), but PgBouncer has
> never actually been in the path.

---

## MT-09 — Per-developer Neon branch is reachable

**Proves** step 0.5. **Not yet run** — needs the Neon account.

Each developer gets a branch off `main` named `dev/<name>`, so nobody is
fighting over one schema while Alembic revisions are still churning. Setup is in
[docs/database-setup.md](docs/database-setup.md) §1.

```bash
psql "postgresql://<user>:<pw>@ep-<id>.<region>.aws.neon.tech/<db>?sslmode=require" -c 'SELECT 1'
```

**Expect** `1`. Note this is the `psql`/libpq spelling — `postgresql://` and
`sslmode`. The application uses `postgresql+asyncpg://` and `ssl`, which is not
the same thing and is the single most common confusion here.

Then, per developer: `cp .env.example .env`, fill in the **pooled** URL as
`DATABASE_URL` and the **direct** one as `DATABASE_URL_DIRECT`, and confirm
`uv run alembic upgrade head` lands on their own branch and nobody else's.

> Last verified — · **Not run.**

---

## MT-10 — The demo fixtures are honest

**Proves** step 1.4. These two files are what the frontend and report
workstreams build against for weeks, and step 5.4 asserts the engine reproduces
the weak one exactly. This is a read-through, not just a validation run.

```bash
cd backend && uv run pytest tests/test_fixtures.py -q
```

Then read the two files and confirm by eye that the honesty properties hold —
the automated tests check them, but these are the ones a reviewer will
challenge, so know why they are the way they are:

- Both captures have `sufficient_for_lattice: false`. A VoIP call produces two
  or three distinct ESP lengths where the cipher-family sieve needs eight
  (LLD §7.2). This failure mode is guaranteed to appear during the live demo.
- The hardened tunnel's `negotiated_lifetime_s` is `unavailable`, citing
  RFC 7296. IKEv2 does not negotiate lifetimes. A number here would be the
  correctness bug the LLD names outright.
- Its `encryption_alg`, `encryption_keylen` and `integrity_alg` are `inferred`,
  not `observed` — the Child SA proposal is inside the encrypted `IKE_AUTH`
  exchange (LLD §6.4).
- Its `pfs_enabled` and `auth_method` are `unavailable`, each with a note that
  explains itself rather than a dash.
- `operating_mode` is `inferred` in **both**, even with a complete IKE capture.
  Tunnel versus transport is not carried in any cleartext field.
- Metadata exposure is 95 against 92. Hardening the cryptography barely moved
  it, which is PRD §4.1's whole argument.

**Expect** 29 passed, and every one of the above to be visibly true in the JSON.

> Last verified 2026-09-04 · Pass. Weak 15/100 `critical`, strong 90/100
> `strong`.

---

## MT-11 — `startup.md` works as written

**Proves** that a new team member can actually get running. Distinct from MT-01,
which proves nothing needed is untracked; this proves the *instructions* are
right. A setup guide nobody re-runs rots quietly, and the person who discovers
it is the one you least want blocked.

Follow [startup.md](startup.md) §2 through §6 **literally**, in a fresh clone, on
a machine where the repo is not already set up. Do not substitute commands you
know work — the point is to catch the step that has silently stopped being true.

```bash
git clone https://github.com/Piyush800x/ipsec-analyzer.git /tmp/mt11
cd /tmp/mt11
cp .env.example .env
# edit .env: DATABASE_URL=sqlite+aiosqlite:///./data/analyzer.db
cd backend && mkdir -p data && uv sync
uv run alembic upgrade head
uv run pytest -q
```

**Expect** `Running upgrade  -> 6173d44f0cce, initial schema`, then
`206 passed, 15 skipped`. Note `.env` is the *only* configuration — if you find
yourself exporting `DATABASE_URL` on the command line to make a step work, the
guide is wrong and needs fixing rather than working around.

**Watch for** counts drifting. Both numbers are quoted in `startup.md` §4 and
§7, and a stale count teaches a newcomer to ignore expected output.

> Last verified 2026-09-04 · Pass — **after fixing a real defect it exposed**.
> `alembic/env.py` read `os.environ` directly and never saw `.env`, so step §4
> failed for anyone following the guide. Every migration run during Phase 1 had
> passed the URL on the command line, which is the one path that always worked.
> This is exactly what MT-11 exists to catch.

---

## MT-12 — The testbed builds a real kernel-ESP tunnel

**Proves** steps 0.1, 0.2 and 2.1, and the LLD §10.3 constraint underneath all
of Phase 2. If ESP is being processed in userspace, every capture in the dataset
is subtly wrong in exactly the dimensions Track B learns from, and nothing else
in the project will tell you.

Kernel XFRM state is namespace-scoped but the modules are not. Load them once
per boot. On Linux:

```bash
sudo modprobe esp4 esp6 ah4 ah6 xfrm_user af_key
```

Under Docker Desktop they belong to the VM, not to your machine:

```bash
docker run --rm --privileged --pid=host alpine \
  nsenter -t 1 -m -u -n -i modprobe esp4 esp6 ah4 ah6 xfrm_user af_key
```

Then:

```bash
cd backend
docker build -f testbed/Dockerfile.peer -t ipsec-testbed-peer:0.1.0 testbed/
REQUIRE_TESTBED=1 uv run pytest tests/test_testbed_docker.py -v
```

**Expect** every test to pass and none to skip. A skip means the daemon, the
kernel modules or the image is missing; `REQUIRE_TESTBED=1` turns that into a
failure naming which one.

Confirm by eye that the ESP is real rather than emulated:

```bash
docker run --rm --entrypoint sh ipsec-testbed-peer:0.1.0 \
  -c 'ls /usr/lib/ipsec/plugins/ | grep -c libipsec'
```

**Expect** `0`. If a `kernel-libipsec` plugin is ever present in this image,
stop and read [LLD §10.3](docs/LLD.md) before doing anything else. Do not enable
it to make a stubborn host work — move to VMs instead.

**The packet-geometry check** is step 0.2, and it validates the premise of
LLD §7.2 before the cipher detector is built on top of it. Run one session and
check the ESP payload lengths of an AES-CBC + SHA1 tunnel:

```bash
uv run python - <<'PY'
import asyncio, struct
from pathlib import Path
from analyzer.core.enums import OperatingMode, TrafficClass
from testbed.config import EspSuite, IkeFlavour, SessionConfig
from testbed.orchestrator import run_session

cfg = SessionConfig(name="geometry", mode=OperatingMode.TUNNEL,
                    ike=IkeFlavour.IKEV2, esp=EspSuite.AES128_SHA1, dh=14,
                    pfs=True, traffic=TrafficClass.ICMP, duration_s=15)
result = asyncio.run(run_session(cfg, Path("/tmp/mt12")))

data = result.pcap.read_bytes()
magic = struct.unpack("<I", data[:4])[0]
endian = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">"
off, lengths = 24, []
while off + 16 <= len(data):
    _, _, caplen, _ = struct.unpack(endian + "IIII", data[off:off + 16])
    off += 16
    pkt, off = data[off:off + caplen], off + caplen
    if len(pkt) < 34 or struct.unpack("!H", pkt[12:14])[0] != 0x0800:
        continue
    ip = pkt[14:]
    if ip[9] != 50:
        continue
    lengths.append(struct.unpack("!H", ip[2:4])[0] - (ip[0] & 0x0F) * 4 - 8)

bad = [n for n in lengths if (n - 16 - 12) % 16 != 0]
print(len(lengths), "ESP packets,", len(bad), "violating (len - IV - ICV) % 16 == 0")
print("distinct lengths:", sorted(set(lengths)))
PY
```

**Expect** zero violations. A violation means the ESP on the wire is not what
LLD §7.2 assumes, and step 9.2 cannot be built as designed.

> Last verified 2026-09-04 · Pass. WSL2 kernel 6.18.33.2, strongSwan 5.9.8.
> 60 ESP packets across two distinct lengths, congruence held for every one.
> `kernel-libipsec` absent from the image; charon loads `kernel-netlink`.

---

## MT-13 — The seven traffic classes look different

**Proves** step 2.6. The **Done when** says to eyeball it, and it means it: two
classes that look alike here will look alike to the classifier in step 9.7, and
discovering that in week nine is far more expensive than discovering it now.

```bash
cd backend
uv run python - <<'PY'
import asyncio
from pathlib import Path
from analyzer.core.enums import OperatingMode, TrafficClass
from testbed.config import EspSuite, IkeFlavour, SessionConfig
from testbed.orchestrator import run_session

out = Path("/tmp/mt13")
for traffic in TrafficClass:
    cfg = SessionConfig(name=f"profile-{traffic.value}", mode=OperatingMode.TUNNEL,
                        ike=IkeFlavour.IKEV2, esp=EspSuite.AES128_SHA1, dh=14,
                        pfs=True, traffic=traffic, duration_s=25)
    result = asyncio.run(run_session(cfg, out))
    print(f"{traffic.value:14s} {result.packet_count:7d} packets")
PY
```

Then open two or three captures in Wireshark — **Statistics → I/O Graph** and
**Statistics → Packet Lengths** — and confirm each class looks like its
description in the table at the top of `testbed/traffic/base.py`.

**Expect** clear separation on at least two axes per class. From the last run,
over 25-second sessions:

| class | pkt/s | mean bytes | distinct sizes | one-directional | idle gaps > 1s |
|---|---|---|---|---|---|
| messaging | 1.0 | 131 | 8 | no | 7 |
| icmp | 9.9 | 348 | 2 | no | 0 |
| voip | 110 | 221 | 4 | no | 0 |
| email | 116 | 1177 | 13 | 81% | 2 |
| video | 204 | 1023 | 75 | 100% | 0 |
| web | 288 | 764 | 9 | no | 10 |
| file_transfer | 2721 | 1004 | 7 | 67% | 0 |

**If two classes look alike**, fix the generator, not the classifier.

Note that `voip` and `icmp` produce very few distinct ESP lengths. That is
correct and deliberate: it is what makes `sufficient_for_lattice` false for them
in step 3.6, which is the honest-failure case the whole demo is built around.

> Last verified 2026-09-04 · Pass. Every class separable on packet rate and on
> at least one of size, directionality or idle structure.

---

## MT-14 — A batch resumes where it was killed

**Proves** step 2.10. Dataset generation (step 8.3) is an eight-hour unattended
job. Laptops sleep and SSH sessions drop, and a batch that cannot resume turns
one interruption into a lost day.

```bash
cd backend
rm -rf /tmp/mt14
uv run python -m testbed.batch /tmp/mt14 --limit 10 --duration 10 &
sleep 90 && kill %1          # kill it partway through
cat /tmp/mt14/manifest.json  # must still parse
uv run python -m testbed.batch /tmp/mt14 --limit 10 --duration 10
```

**Expect** the second invocation to log `already done, skipping` for each
session the manifest records as completed, and to run only the remainder. The
manifest must parse after the kill — it is written to a sibling and moved into
place precisely so a process killed mid-write leaves the previous one intact.

Then confirm nothing was left behind:

```bash
docker ps -a --filter label=ipsec-analyzer.testbed
docker network ls --filter label=ipsec-analyzer.testbed
```

**Expect** both empty. A killed process never runs its `finally`, so the next
`run_batch` prunes orphans on startup. If these are *not* empty after the second
invocation, that pruning is broken, and a long batch will exhaust the address
pools of the daemon with a symptom — "all predefined address pools have been
fully subnetted" — that says nothing about the cause.

> Last verified 2026-09-04 · Pass. A 10-session batch was `SIGKILL`ed after 7
> sessions. The manifest still parsed; the hard kill left 2 orphaned containers
> and 1 network behind, as expected, since `SIGKILL` runs no `finally`. The
> resume cleaned all three up, skipped exactly those 7, ran the remaining 3, and
> finished with zero orphans. Separately, 20 `peer_pair` cycles leaked nothing
> (`TESTBED_SLOW=1 pytest -k NoResourceLeaks`).
>
> Note: pipe the batch to a file, not to `head`. Truncating the pipe sends
> `SIGPIPE` to the batch mid-session and produces a spurious "cannot exec in a
> stopped container" failure that looks like a testbed bug and is not one.

---

## MT-15 — Reader packet count matches tshark on a real capture

**Proves** step 3.2. The automated suite (`tests/test_ingest_reader.py`)
validates the reader's decoding logic against synthetic pcap files built by
hand, because no Docker daemon was available to produce a real testbed
capture when Phase 3 landed. That is a test of the code against itself; it is
not step 3.2's actual Done-when condition, which compares against `tshark` on
a real capture from the Phase 2 testbed.

```bash
cd backend
uv run python -m testbed.batch /tmp/mt15 --limit 1 --duration 30
CAP=/tmp/mt15/*/capture.pcap
tshark -r $CAP | wc -l
uv run python -c "
from pathlib import Path
from analyzer.ingest.reader import read_packets
import glob
path = Path(glob.glob('/tmp/mt15/*/capture.pcap')[0])
print(len(read_packets(path).packets))
"
```

**Expect** the two counts to match exactly.

**If they do not match**, check first whether the difference is pcapng versus
classic pcap — `ingest/reader.py` only reads classic pcap, matching what
`testbed/capture.py`'s `tcpdump -w` produces, and will raise `IngestError`
rather than silently misreport on anything else.

**Running it without tshark on the host.** The pinned tshark lives in the
backend image (MT-02), so the comparison can be made against *that* binary
rather than whatever the host happens to have — which is stricter, since the
pinned version is the one Track A actually parses:

```bash
docker run --rm -v "$PWD/dataset:/data" --entrypoint sh \n  ipsec-analyzer-backend:0.1.0 \n  -c "tshark -r /data/sessions/weak-reference/capture.pcap 2>/dev/null | wc -l"
```

> Last verified 2026-09-07 · Pass, against tshark 4.4.18 in
> `ipsec-analyzer-backend:0.1.0`, on four real testbed captures spanning both
> IP versions, both IKE versions and three cipher suites. Every count matched
> exactly:
>
> | capture | tshark | reader |
> |---|---|---|
> | `weak-reference` (IKEv1, 3DES, v4) | 7120 | 7120 |
> | `hardened-reference` (IKEv2, AES-GCM, v4) | 7123 | 7123 |
> | `s003-…-tunnel-v6-messaging` (IKEv1, AES-CBC, v6) | 678 | 678 |
> | `s019-…-tunnel-v6-messaging` (IKEv2, 3DES, v6) | 684 | 684 |

---

## MT-16 — Track A matches labels.json on a real testbed capture

**Proves** step 4.8, and is the single most important check in this file for
Track A's credibility. The automated suite (`tests/test_track_a_*.py`)
validates every parsing rule against hand-built tshark JSON, because no
tshark binary was available when Phase 4 landed — see CHANGELOG.md's Phase 4
"Not verified" entry. That proves the parsing *logic*; it says nothing about
whether tshark's real JSON matches what `ike_parser.py` assumes it calls
things, which is exactly the failure mode LLD section 6.1 warns is silent.

```bash
cd backend
uv run python -m testbed.batch /tmp/mt16 --limit 1 --duration 30
DIR=$(dirname "$(ls /tmp/mt16/*/capture.pcap)")
tshark -r "$DIR/capture.pcap" -Y isakmp -T json --no-duplicate-keys > /tmp/mt16.json
uv run python -c "
import json
from pathlib import Path
from analyzer.ingest.reader import read_packets
from analyzer.ingest.flow import assemble_flows
from analyzer.track_a.correlate import run_track_a

d = Path('$DIR')
packets = read_packets(d / 'capture.pcap').packets
pairs = assemble_flows(packets)
sas = run_track_a(d / 'capture.pcap', pairs)
expected = json.loads((d / 'labels.json').read_text())['expected']
for sa in sas:
    print('ike_version:', sa.ike_version.value, 'vs', expected['ike_version'])
    print('dh_group:', sa.dh_group.value, 'vs', expected['dh_group'])
    print('encryption_alg (INFERRED, may legitimately differ):', sa.encryption_alg.value, 'vs', expected['encryption_alg'])
"
```

**Expect** `ike_version`, `ike_exchange_mode` (IKEv1 only), `dh_group`,
`prf_alg` (IKEv2 only), `auth_method` and `negotiated_lifetime_s` (IKEv1
only) to match `expected` exactly, with `OBSERVED` provenance. **Do not**
expect `encryption_alg`/`encryption_keylen`/`integrity_alg` to match when the
session's ESP suite is a GCM variant — CHANGELOG's Phase 4 open spec question
explains why the same-family `INFERRED` guess is expected to diverge there,
and that is correct behaviour, not a bug.

**If the raw JSON's field names do not match what `ike_parser.py` assumes**
(check `_find_first`/`_find_by_suffix` calls in `parse_isakmp_json` and its
helpers against the actual keys in `/tmp/mt16.json`), that is the real
finding this check exists to make. Fix the adapter, not the assumption.

> Not yet run. Needs Docker, a kernel with XFRM, and a `tshark` binary on the
> host (same prerequisites as MT-12 and MT-15), none of which were available
> where Phase 4 was implemented. This is the highest-priority manual check
> outstanding in this file.

---

## MT-17 — Both reports read correctly to their audience

**Proves** steps 10.2 and 10.3. The automated tests assert that specific
sentences are present; whether the executive report is *actually readable by a
non-technical reader* is not something a test can decide, and it is the
Done-when.

```bash
cd backend
uv run python -c "
from pathlib import Path
from analyzer.core.schema import Assessment
from analyzer.report.render import render_pdf
a = Assessment.model_validate_json(Path('tests/fixtures/assessment_weak.json').read_text())
for fmt in ('executive', 'technical'):
    Path(f'/tmp/{fmt}.pdf').write_bytes(render_pdf(a, fmt, rule_count=14))
"
xdg-open /tmp/executive.pdf
```

**Expect**, reading only the executive PDF and knowing nothing about IPsec:
you can say what is wrong ("it uses an obsolete cipher and an exchange mode
that leaks the password hash") and what to do about it ("switch to AES-256-GCM
and IKEv2, rotate the pre-shared key"). No hex, no packet numbers, no rule IDs.

**Expect**, in the technical PDF: every finding carries its evidence; the
parameter table shows observed/inferred/unavailable per row with the reason
spelled out for each unavailable one; and the limitations section states the
AES key-length case explicitly.

> Last verified 2026-09-05 · Pass. Both render from the fixtures; the
> executive report is 2 pages and the technical 6. The unavailable rows read
> as sentences rather than dashes, which was the thing worth checking by eye.

---

## MT-18 — The offline stack runs with no outbound network

**Proves** step 11.4, NFR-3 and NFR-6. Compose topology is the kind of claim
that is either true or quietly false, and only a run tells you which.

```bash
docker compose -f docker-compose.offline.yml up --build -d
docker compose -f docker-compose.offline.yml ps

# The backend must have no route off the box at all.
docker compose -f docker-compose.offline.yml exec backend \
  python -c "import socket; socket.create_connection(('1.1.1.1', 53), timeout=5)"
```

**Expect** both services healthy, <http://localhost:3000> serving the
dashboard, and that last command to **fail** with a network-unreachable error.
If it succeeds, the `internal: true` network is not doing what the file claims
and NFR-6 is unproven.

Then upload a capture through the UI and confirm an assessment appears.

> Last verified 2026-09-07 - Pass. Both services healthy; the backend's
> `create_connection(('1.1.1.1', 53))` failed with `OSError: [Errno 101]
> Network is unreachable`, and <http://localhost:3000> served HTTP 200.
>
> **The first run of this found four defects, none of which any test could
> see.** Every one produced a stack that came up and looked right:
>
> 1. `frontend/` had no `.dockerignore`, so the build context included a
>    directory npm had created under the reserved Windows name `NUL`. The
>    daemon cannot read that path, so the frontend image would not build at all
>    (`error from sender: open frontend\NUL: Incorrect function`) - and because
>    `NUL/` is gitignored, it is invisible in `git status`.
> 2. The compose `command:` ran `uv run alembic` and `uv run uvicorn`. `uv run`
>    re-resolves the environment, which needs an index, which needs DNS - on an
>    `internal: true` network. The backend died with "Could not connect, are you
>    offline?", which was the correct answer to the wrong question.
> 3. That `command:` was a YAML `>` folded block whose continuation lines were
>    indented further than the first, so the newline was preserved and `sh`
>    received two commands. The second began `--host`.
> 4. `libgomp1` was missing from the backend image, so `import lightgbm` failed
>    and **both** trained models were skipped - see MT-26, which exists because
>    of exactly this class of failure.

---

## MT-19 — Demo rehearsal, three clean runs

**Proves** step 11.6. Rehearse on the offline stack — Neon scales to zero and
a cold start mid-demo is an avoidable risk.

Run the PRD §16 script end to end three times: upload the weak capture,
analyse, walk the findings, open the comparison against the hardened one,
download the executive report. Time it against the two-minute target.

**Expect** three consecutive runs with no restarts, no stalls on the progress
bar, and the comparison view rendering both tunnels side by side.

**`scripts/demo_rehearsal.py` runs the sequence and asserts on it**, rather
than timing a person clicking. It checks the thing each step is on stage to
show - that tunnel A's findings are not empty and B's list is shorter, that B
scores *higher*, that the classifier returned a class, that the report really
is a PDF - so a run that is fast and wrong fails instead of passing.

```bash
docker compose -f docker-compose.offline.yml up -d --build
python scripts/demo_rehearsal.py --runs 3
```

> Last verified 2026-09-07 - **3/3 clean, 21.1-21.2 s each** against the
> two-minute target, and identical to the finding across all three runs:
>
> | step | result | |
> |---|---|---|
> | 1. tunnel A (weak) | score **25**, 7 findings, 1 critical | 8.4 s |
> | 2. traffic classifier | **voip at confidence 1.0, exposure 100** | 0.0 s |
> | 3. tunnel B (hardened) | score **80** (+55), 2 findings | 8.4 s |
> | 3b. comparison | delta 55, 5 findings only in A | 2.1 s |
> | 4. executive report | 17 KB PDF | 2.4 s |
>
> The three runs agreeing exactly is NFR-4 visible from outside: the engine is
> a pure function of its inputs, so the same capture twice is the same
> assessment twice.
>
> **What still needs a person.** This harness drives the API, not the browser.
> It does not prove the dashboard *renders* - that the threat matrix lights up,
> that the progress bar moves rather than jumping from 0 to 100, that the
> comparison view puts the two tunnels side by side. Walk those by eye at
> <http://localhost:3000> before the demo; they are what the audience sees.

---

## MT-20 — The backend starts and reports on Windows *and* Linux

**Proves** that the API has no hidden native-library dependency at import
time, and that the PDF backend's absence degrades instead of crashing.

An automated test cannot settle this alone: the failure it guards was an
`OSError` raised during *module import*, which takes the test suite down at
collection rather than failing a test. `test_importing_the_api_does_not_import_weasyprint`
covers the import graph in a subprocess, but only a human running the real
server on each OS confirms the whole path.

Run this on **both** a Windows box with no GTK runtime and a Linux box with
WeasyPrint's libraries installed. The two are expected to differ in exactly
one place, marked below.

```bash
cd backend
uv run pytest                       # must collect and run everything
uv run uvicorn analyzer.api.main:create_app --factory --port 8000
```

In a second shell, with `<id>` from an assessment you have analysed:

```bash
curl -s localhost:8000/api/v1/health
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' \
  "localhost:8000/api/v1/assessments/<id>/report?format=technical&inline=1"
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' \
  "localhost:8000/api/v1/assessments/<id>/report?format=technical"
```

**Expect**

| | Windows, no GTK | Linux, WeasyPrint installed |
|---|---|---|
| `pytest` | passes, PDF tests **skipped** | passes, PDF tests **run** |
| server startup | clean | clean |
| `/health` | `{"status":"ok",...}` | same |
| report `?inline=1` | `200 text/html` | `200 text/html` |
| report as PDF | `503 application/problem+json` | `200 application/pdf` |

**Watch for** the 503's `detail` naming both the way out now (`?inline=1`)
and the fix (the GTK3 runtime). A 503 with a bare title is the failure this
check exists to catch — it leaves the reader with a dead end. Also watch for
WeasyPrint's multi-line installation banner appearing on stdout more than
once across repeated PDF requests: that means the failed-import cache
regressed and the dlopen probe is re-running per request.

> Last verified 2026-09-06 · Windows 10 Pro 19045 **and** Linux 7.0.0-30-generic ·
> **Pass on both.** The Linux column was confirmed against a running server:
> `/health` returned `{"status":"ok","database":"up","version":"0.1.0"}`,
> `?inline=1` returned `200 text/html; charset=utf-8`, and the PDF returned
> `200 application/pdf`. The WeasyPrint banner did not reappear across repeated
> requests, so the failed-import cache is holding.

---

## MT-21 — A real capture goes through the running API end to end

**Proves** that the pipeline works against a *running server*, which is not the
same claim as the test suite passing. It was written because it caught a defect
the suite could not: every capture with enough ESP length diversity for the
cipher sieve to answer returned **HTTP 500**, because Track B wrote a suite
label into an enum-typed contract field and `model_copy(update=...)` does not
validate. Every unit test asserted on the attribute the sieve returned; none
carried a successful inference into a validated `Assessment`.

The lesson generalises, so this check stays: **analyse a capture the sieve can
actually answer.** A capture that degrades exercises the honest-gap paths and
nothing else, and those are the paths already covered.

```bash
cd backend && mkdir -p data && uv run alembic upgrade head
uv run uvicorn analyzer.api.main:create_app --factory --port 8000
```

In a second shell — the payload lengths matter, see below:

```bash
uv run python -c "
import sys; sys.path.insert(0, 'tests')
from pathlib import Path
from _pcap import DLT_EN10MB, esp_payload, eth_frame, ipv4_packet, write_pcap
f  = [eth_frame(ipv4_packet('10.0.0.1','10.0.0.2',50,esp_payload(1,i,b'X'*(48+(i%13)*16)))) for i in range(1,200)]
f += [eth_frame(ipv4_packet('10.0.0.2','10.0.0.1',50,esp_payload(2,i,b'Y'*(48+(i%11)*16)))) for i in range(1,200)]
write_pcap(Path('/tmp/demo.pcap'), DLT_EN10MB, f)"

curl -s localhost:8000/api/v1/health
CAP=$(curl -sF file=@/tmp/demo.pcap localhost:8000/api/v1/captures | jq -r .id)
RUN=$(curl -sX POST localhost:8000/api/v1/captures/$CAP/analyze | jq -r .runId)
curl -s localhost:8000/api/v1/runs/$RUN | jq '{status, stage, error, assessmentId}'
AID=$(curl -s localhost:8000/api/v1/runs/$RUN | jq -r .assessmentId)
curl -s localhost:8000/api/v1/assessments/$AID | jq '.security_associations[0].encryption_alg'
curl -so exec.pdf -w '%{http_code} %{content_type} %{size_download}\n' \
  "localhost:8000/api/v1/assessments/$AID/report?format=executive"
curl -so tech.pdf -w '%{http_code} %{content_type} %{size_download}\n' \
  "localhost:8000/api/v1/assessments/$AID/report?format=technical"
```

**Expect**

| | |
|---|---|
| run `status` | `succeeded`, `error` null, `assessmentId` populated |
| `encryption_alg` | `provenance: "inferred"` with a **confidence**, value an `EncryptionAlg` member |
| `encryption_keylen` | `unavailable` with a note — FR-4.9 holds even when the family is known |
| both reports | `200 application/pdf`, tens of kilobytes |
| an unknown assessment id | `application/problem+json`, never a bare `{"detail": ...}` |

**Watch for** a `status: failed` whose `error.detail` mentions *validation* —
that is this check's original quarry, and it means something upstream is
writing a value the contract does not accept. Also watch the `stage` field on a
failure: `ingest` here meant the whole document failed validation at the end,
not that reading the pcap broke.

**Note** the run completes with Track A unavailable unless `tshark` is on
`PATH`; the log says so explicitly. That is the honest degradation, not a
failure, but it does mean this check does not exercise Track A.

> Last verified 2026-09-06 · Linux, SQLite, no tshark · **Pass.** 398-packet
> 78 KB capture. Run reached `succeeded`; score 100 `strong` (nothing was proven
> wrong, so nothing was deducted); executive report 12,918 bytes, technical
> 32,042 bytes; unknown id returned RFC 9457. Before the fix, this exact
> sequence returned `status: failed` with two `Assessment` validation errors.

---

## Adding a check

Copy this. Keep it short enough that someone will actually run it.

```markdown
## MT-NN — <what a human confirms>

**Proves** step X.Y. <Why an automated test cannot settle this.>

​```bash
<copy-pasteable commands>
​```

**Expect** <the specific observable outcome, not "it works">.

**Watch for** <the plausible-looking wrong result, if there is one>.

> Last verified YYYY-MM-DD · <version or commit> · Pass/Fail · <notes>
```

Then add a row to the Status table, and note the new check in
[CHANGELOG.md](CHANGELOG.md) under the step that introduced it.

---

## MT-22 — Every traffic class carries real traffic over IPv6

**Proves** the IPv6 generator fix. Half the sampled matrix is IPv6, and for
Phases 2 through 8 every one of those sessions brought its tunnel up, generated
nothing, and was written with a `labels.json` claiming 90 seconds of its class.
The captures held eight to eleven packets: the IKE exchange and the DELETE.

The automated tests catch the *command lines* — `tests/test_testbed_traffic.py`
asserts that no listener binds `0.0.0.0` and no IPv6 literal appears unbracketed
in a URL, for every class in both families. They cannot catch a tool that
accepts its arguments and still sends nothing, which is why a person runs this.

```bash
cd backend
uv run python - <<'PY'
import asyncio
from pathlib import Path
from testbed.config import IpVersion
from testbed.orchestrator import run_session
from testbed.sampler import load_matrix, sample_configs

out = Path("/tmp/mt22")
configs = {c.traffic: c for c in sample_configs(load_matrix()) if c.ip is IpVersion.V6}
for traffic, cfg in sorted(configs.items(), key=lambda kv: kv[0].value):
    session = cfg.model_copy(update={"duration_s": 40, "address_index": 5})
    try:
        result = asyncio.run(run_session(session, out))
        print(f"{traffic.value:14s} {result.packet_count:7d} packets")
    except Exception as exc:
        print(f"{traffic.value:14s} FAILED: {exc}")
PY
```

**Expect** every class in the hundreds or thousands, never in the tens. A count
below the ESP floor now raises rather than being written, so a regression shows
as `FAILED: the tunnel came up but carried almost nothing` — but read the
numbers anyway. A class that fell from thousands to fifty would clear the floor
and still be broken.

> Last verified 2026-09-07 · icmp 410, messaging 32, file_transfer 56201,
> web 21873, video 4969, voip 3976 over 40s; email 705 · Pass · email needed
> `libio-socket-inet6-perl` and `netbase` in the peer image before swaks would
> speak IPv6 at all.

---

## MT-23 — Concurrent shards produce one complete, disjoint dataset

**Proves** step 8.3's sharding. Several processes writing into one directory,
each on its own Docker subnet and its own manifest, must between them produce
every configuration exactly once. The two failure modes are silent and opposite:
a session generated twice wastes an hour, one generated never leaves a hole that
surfaces only as a missing configuration during training.

```bash
cd backend
for i in 1 2 3 4 5 6; do
  uv run python -m testbed.batch ../dataset/sessions \
      --repeats 4 --duration 90 --shard $i/6 > ../dataset/gen6-$i.log 2>&1 &
done
wait

uv run python - <<'PY'
from pathlib import Path
from testbed.sampler import load_matrix, sample_configs, with_repeats

expected = {c.name for c in with_repeats(sample_configs(load_matrix()), 4)}
on_disk = {p.name for p in Path("../dataset/sessions").iterdir() if p.is_dir()}
print(f"expected {len(expected)}, on disk {len(on_disk)}")
print("missing:", sorted(expected - on_disk)[:10])
print("unexpected:", sorted(on_disk - expected)[:10])
PY
```

**Expect** `unexpected` empty, and `missing` empty or a short list the logs
record as failed — `grep failed: ../dataset/gen6-*.log` — rather than sessions
that vanished without a reason.

Watch for `Pool overlaps with other one on this address space` in any log. That
means two shards drew the same subnet, which `--shard I/N` setting
`address_index` to `I-1` should make impossible, and it fails every session in
the losing shard.

**If changing the shard count**, seed the new manifests first. They are named
`manifest-I-of-N.json`, so going from 3 shards to 6 starts with empty manifests
and regenerates everything already done.

> Last verified 2026-09-07 · 6 shards, 248/248 sessions, 0 failures, 14 GB ·
> Pass · shards completed in 1435–1640s each having skipped 26–28 seeded
> sessions apiece.

---

## MT-24 — The model card describes the artefacts actually on disk

**Proves** step 9.8's documentation half. `docs/model-card.md` is generated from
`models/metrics.json`, and the reason it is generated rather than written is
that a hand-written card describes the run someone remembers.

```bash
cd backend
uv run python -m analyzer.track_b.model_card
git diff --stat ../docs/model-card.md
```

**Expect** no diff. A diff means the card in git was written against different
artefacts than the ones in `models/`, so the numbers a reader would quote are
not the numbers the deployment produces.

Then read it, and check two things by eye:

1. **The class count.** If the card opens with "This is an N-class model, not a
   7-class one", every macro-F1 in it is averaged over N classes and must not be
   compared to PRD §8.4's target as though it covered seven. Six classes handled
   perfectly averages 0.857, which clears a 0.85 threshold while a seventh of
   the problem was never attempted.
2. **The Limitations section** is still true of this build, and any target
   marked `**NOT MET**` is recorded as unmet in [CHANGELOG.md](CHANGELOG.md)
   rather than only here.

---

## MT-25 — A tunnel still rekeys, and does it on time

**Proves** step 9.3, and guards a failure no automated test can see: a change to
the lifetime settings that stops SAs rekeying at all.

Nothing in the sampled matrix demonstrates this. Every matrix row runs a
3600-second lifetime for 90 seconds, so no dataset session ever rekeys inside
its own capture — right for a dataset, useless for this measurement.
`testbed/rekey_probe.py` exists to make it happen.

```bash
cd backend
uv run python -m testbed.rekey_probe /tmp/mt25

uv run python - <<'PY'
from pathlib import Path
from analyzer.ingest.flow import assemble_flows
from analyzer.ingest.reader import read_packets
from analyzer.track_b import replay

result = read_packets(Path("/tmp/mt25/rekey-300s/capture.pcap"))
series = replay.spi_series(assemble_flows(result.packets))
for (src, dst), entries in series.items():
    base = entries[0][1]
    print(f"{src} -> {dst}: offsets {[round(ts - base, 1) for _, ts in entries]}")
    print(f"   observed_rekey_s = {replay.observed_rekey_s(entries).value}")
PY
```

**Expect** at least three SPIs per direction, at offsets near 0, 290 and 580,
and an `observed_rekey_s` within 10% of 300. Two rotations rather than one is
the point: a single rotation cannot distinguish "rekeyed on time" from "rekeyed
once, for some other reason".

**Two failures to watch for**, neither of which looks like a failure:

- **Two SPIs and a capture that stops dead at the rekey moment.** `over_time` is
  too small for the rekey to complete — strongSwan *deletes* an SA that has not
  rekeyed within `rekey_time + over_time`, so a zero window expires it at the
  instant it tries. The session is still recorded as successful, and the traffic
  before the expiry is real, so the ESP-count guard does not catch it.
- **An interval of 0 at 0.95 confidence.** The SPI series was built from one
  `SAPair`'s two directions, which come up together, rather than across
  generations. See `replay.spi_series`.

> Last verified 2026-09-07 · 700s capture, 55288 packets, SPI offsets
> 0/288.5/578.5 in both directions, observed_rekey_s 290 vs 300 configured
> (3.3%) · Pass

---

## MT-26 — The backend image actually carries the trained models

**Proves** that step 11.4's image can do what the demo needs it to do, and
guards a failure with **no error anywhere in it**.

`docker-compose.offline.yml` sets `MODEL_DIR=/app/models`. `track_b/service.py`
is deliberately written to degrade rather than fail: a missing model directory
produces `UNAVAILABLE` with a reason on every model-backed attribute and the
analysis completes normally. That is exactly right for a deployment with no
models, and catastrophic for this one, which has them committed — the image
builds clean, starts clean, serves clean, and PRD §16's second demo step has
nothing to show.

`backend/Dockerfile` never had a `COPY models` at all — written before the
artefacts were committed, and so correct when written and silently wrong
afterwards. No test that does not open the image could catch it.

```bash
cd backend
docker build -t ipsec-analyzer-backend:0.1.0 .
docker run --rm --entrypoint sh ipsec-analyzer-backend:0.1.0   -c "ls -1 /app/models"
```

**Expect** every *tracked* artefact in `backend/models/` to be listed — in
particular `traffic_lightgbm.txt`, `mode_lightgbm.txt`, `calibration.json` and
their `.meta.json` files. Eight files.

`traffic_cnn.pt` should **not** appear, and its absence is not a fault: the CNN
is a training artefact, inference loads the LightGBM booster so that torch is
not a runtime dependency, and it is gitignored. A shorter listing than eight
means `.dockerignore` is eating something that matters.

Then confirm the running stack agrees, which is the part a directory listing
cannot tell you:

```bash
docker compose -f docker-compose.offline.yml up --build -d
python scripts/demo_rehearsal.py --runs 1
```

**Expect** step 2 of the rehearsal to name a traffic class and a confidence.
If it reports "the traffic classifier identified no inner traffic class", the
models are not reaching the running process even if they are in the image —
check `MODEL_DIR` against the path they were copied to.

> Last verified 2026-09-07 - Pass, after three separate fixes. All eight
> tracked artefacts are in `/app/models`, and the rehearsal reports `voip at
> confidence 1.0`.
>
> **It took three fixes because there were three independent breaks, and each
> produced the same silent symptom.** Any one of them alone would have left the
> demo with nothing to show at step 2:
>
> 1. `backend/Dockerfile` had no `COPY models`, so the directory did not exist.
> 2. `libgomp1` was missing, so LightGBM could not import and both models were
>    skipped even once the files were there.
> 3. `JobRunner` never passed `Settings.model_dir` to the pipeline, so even a
>    perfect image analysed every capture model-free. This one was not specific
>    to the container: **`MODEL_DIR` had never worked on any deployment**, and
>    `tests/test_api_jobs.py::test_the_configured_model_dir_reaches_the_pipeline`
>    now holds that path open.
>
> `models/*.pt` staying out of the image is **correct**, not a fourth break:
> `traffic_cnn.pt` is the CNN, inference loads the LightGBM booster so that
> torch is not a runtime dependency, and the file is gitignored — a clean clone
> does not have it either. The listing below is what a clean clone produces.

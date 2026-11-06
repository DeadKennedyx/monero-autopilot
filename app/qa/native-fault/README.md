# Native payment fault tests

This QA-only harness runs the actual desktop UI and production `Sender`, PIN,
journal, gateway and Tor checks against a controlled node proxy. It adds no
switch, hook or relaxed validation to the product. It is not an installer or a
production download. Nothing starts merely by importing or testing `core.mjs`.

The proxy serves one dedicated Tor onion service on loopback and forwards each
allowed request exactly once through that helper Tor's SOCKS5h listener to the
existing `OWNED_NODE` read from the product source. It never resolves onion
names through Windows DNS, follows redirects, accepts incoming credentials,
forwards wallet RPC methods, or falls back to a direct connection. Requests are
limited to the product daemon path/method allowlist, 1 MiB bodies and 32 MiB
responses, with eight concurrent requests. Upstream bulk reads get the same
180-second budget as the product; other reads and broadcasts retain 25 seconds.
The proxy passes bounded binary block requests through byte-for-byte and never
changes block history, restore heights, output requests or signed transactions.
The listener uses a 120-second idle keep-alive timeout, longer than the product
client's idle connection pool, to keep normal polling separate from the fault.
The broadcast schema includes Monero's standard `rpc_access_request_base.client`
field; the harness forwards it unchanged and does not log it.

All run files stay under ignored `app/.runtime/native-fault/<run-id>/`.
There are no commands for copying or selecting an existing wallet profile.
The native launcher always supplies this run's `profile` directory explicitly.
The app itself creates/protects the wallet directory. The helper protects the
run directory for the current Windows user and SYSTEM before starting Tor.

## Prerequisites and evidence limits

- Windows, Node 24+, the app's installed dependencies, verified Tor/Monero files
  and Rust toolchain must already exist. These scripts do not install them.
- Wait until source changes are finished before preparing/building an overlay.
  Stage intended new source files first; a commit is not needed. Existing tracked
  source is copied from the working tree, including current reviewed fixes.
- Both endpoints must be controlled wallets. Funding is a separate authorized
  step: the harness does not fund wallets or grant permission to send money.
- An overfee preview needs enough spendable funds for Monero to construct the
  non-relayed transaction. An insufficient-funds error is not a SEND-06 pass.
- This adds a second Tor circuit and may be slower than the ordinary route.
- The overlay uses exactly three identity/endpoint edits: the pinned node
  constant, the native QA window title, and Tauri product name/identifier. All
  other copied source bytes match the recorded snapshot. Production payment
  limits, PIN authorization and durable attempt checks remain unchanged.
- Record the QA executable hash, source snapshot, injected fault, actual native
  actions, timestamps and results. Passing policy tests does not establish a
  native or funded-wallet pass. The production release still needs its own
  unchanged-route smoke test.

## Prepare a run (do not run while source edits are in progress)

Run these commands from `app`. Use a fresh ID and two unused local ports. The
first command only creates configuration; the second explicitly starts two
hidden helper processes, not a wallet.

```powershell
node qa/native-fault/prepare-run.mjs payments-01 19050 19089
pwsh -NoProfile -File qa/native-fault/start-helpers.ps1 -RunId payments-01
node qa/native-fault/control.mjs payments-01 status
```

Wait until `.runtime/native-fault/payments-01/tor-service/hostname` exists. Tor
may need additional time to establish circuits. A preexisting/occupied listener
is not adopted. If helpers fail, inspect the run's helper logs; do not disable
Windows security or change production proxy configuration to force a pass.

Snapshot and build only when the root task confirms the final source is stable:

```powershell
node qa/native-fault/prepare-overlay.mjs payments-01
pwsh -NoProfile -File qa/native-fault/build-overlay.ps1 -RunId payments-01
pwsh -NoProfile -File qa/native-fault/run-overlay.ps1 -RunId payments-01
```

Preparation does not build or launch. It refuses an existing overlay and checks
that inputs did not change during copying. It creates junctions only to the
app's build dependencies (`node_modules`) and verified public tooling (`.tools`),
never to `.runtime` or a wallet profile. The build uses its own Cargo target
directory and creates `monero-autopilot-qa.exe`, leaving the product executable
untouched. Its window title says **QA FAULT TEST — CONTROLLED WALLET ONLY**.

Create a new QA PIN/wallet through that native UI. Keep any recovery information
private. Fund only the explicitly selected controlled QA wallet with the
authorized amount, wait for spendable funds, and record the funding separately.
In the default `read-only` proxy mode every broadcast is refused.

## SEND-06: fee exceeds the cap

The override is **atomic units per transaction weight**, not a fabricated total
fee. The official wallet still constructs the transaction and returns its exact
fee. The proxy preserves other response fields (including quantization) and
fails closed if the upstream fee schema is not recognized.

```powershell
node qa/native-fault/control.mjs payments-01 overfee 100000
```

The command waits for an `applied` acknowledgment. Close and reopen the **QA app**
normally if needed to clear the wallet's cached fee estimate; preserve its run
and profile. Do not restart/copy the funded production wallet.

1. In the native QA app, enter a controlled recipient and an authorized amount.
2. Click **Review payment**. Observe the exact returned fee and maximum.
3. A pass requires a fee strictly over `0.0001 XMR`, an explanation of the cap,
   no authorizable preview, and no broadcast. Repeated snapshot refreshes should
   not erase the rejection while the user is reading it.
4. Inspect `control ... status`: `broadcasts`, `accepted` and `dropped` remain 0;
   `proxy.log` includes `fee_estimate_overridden`. No transfer is confirmed.

If construction fails for insufficient funds, the case is incomplete: reduce
the per-weight override or obtain separately authorized funding. Do not lower
the production fee cap or fake a successful preview. The proxy independently
refuses all broadcasts while the overfee mode is active.

Restore real estimates, then normally restart the QA app to clear cached fees:

```powershell
node qa/native-fault/control.mjs payments-01 read-only
```

## SEND-13: node accepts, response is lost

Use the same isolated run after finishing SEND-06, or create another fresh run.
Prepare a normal `0.0001 XMR` payment to a controlled wallet in the native UI.
Review the exact fee and confirm that it does not exceed `0.0001 XMR`.

Immediately before the one authorized confirmation, arm the fault:

```powershell
node qa/native-fault/control.mjs payments-01 drop-next
```

After the acknowledgment, manually check the approval box, enter the QA PIN and
confirm **once**. The proxy durably consumes its one-broadcast budget before any
upstream I/O. It forwards that broadcast once. Only after the real owned node
returns successful `status: OK` without `not_relayed`/`double_spend` does it close
the response connection. It does not drop a frontend `/api/send` acknowledgment.

Observe the native app's original transaction and its checking/uncertain state.
New preparation must stay blocked while unresolved. Use **Check status**, normal
reconnection and an orderly restart to observe reconciliation of the original
txid. Keep wallet funds/transaction references in private ignored evidence.

Expected proxy evidence is `broadcasts: 1`, `accepted: 1`, `dropped: 1`, with
`accepted_response_dropped` in `proxy.log`. Subsequent broadcast requests are
denied, including after helper restart; read requests continue. The budget can
never be rearmed within that run. A network failure before acceptance consumes
the budget too and reports `upstream_failed_no_retry`; that is an inconclusive
fault setup, not proof of accepted-but-response-lost. Reconcile first and never
blindly retry the original payment.

Monero can discover a pending transaction quickly. If the transient uncertain
screen is not observed, record that limit rather than claiming it was seen.
The accepted/drop counters plus reconciliation establish a different part of
the case; native UI observations must be documented independently.

## Evidence and shutdown

`proxy-state.json`, `proxy.log` and command acknowledgments contain only fixed
method/outcome names, fee settings and counters. The proxy never logs request
bodies, signed transaction bytes, addresses, txids, headers or credentials.
Tor service keys and all wallet evidence remain private under the run directory.
Do not commit any run directory or publish a QA executable as a release.

Use **Save & quit** in the QA app, wait for its native process and readiness file
to disappear, and stop only the helper processes recorded for that run:

```powershell
pwsh -NoProfile -File qa/native-fault/stop-helpers.ps1 -RunId payments-01
```

The helper-stop script verifies PID, executable path and process start time and
preserves all evidence. Stopping an in-flight broadcast cannot cancel/revoke it;
always reconcile its original outcome after restarting. Do not delete or reset
`proxy-state.json` to obtain another broadcast allowance. A later independent
authorized test needs a new run. Keep any remaining controlled-wallet funds and
their recovery information until the original transaction is resolved.

## Isolated checks

### Local reply suppression alternative

For the accepted-response-loss and route-outage cases, an isolated overlay can
keep the production owned endpoint and normal single Tor route. Prepare a fresh
run, then use `prepare-overlay.mjs <run-id> --local`. Do not start that run's proxy
helpers. This mode changes only the copied transport file and the two QA identity
files; the manifest records `local-accepted-reply-loss`. `local-fault.rs` is a
template appended to the isolated copy, never part of the production crate.

The default denies broadcasts. Immediately before the authorized native payment,
write the exact bytes `drop-next` to the run's `local-mode` file. Before upstream
I/O the copied transport exclusively creates and flushes `broadcast-claimed`.
That file is permanent and cannot be rearmed. After a real successful node reply,
it creates and flushes `accepted-reply-suppressed`, then returns transport failure
instead of passing the success to Monero. This yields an unavailable response
from the local gateway, not a dropped frontend acknowledgment. A failed upstream
request consumes the claim without establishing acceptance. Never delete either
evidence marker to retry. No signed bytes, response bodies or secrets are logged.

For an outage, create the empty `offline` file in that isolated run. It rejects
all remote requests before I/O. Remove only that explicit marker to restore the
normal route, then exercise **Try again** in the desktop. The marker does not
change any Windows network or security setting. A live pass still requires
native observations, the original transaction outcome, and unchanged-route
production smoke testing. The template's unit test checks the durable single
broadcast budget and accepted-only reply suppression.

These tests operate entirely in memory with fake upstream functions. They open
no listeners and start no Tor, app, wallet or transaction:

```powershell
node --test qa/native-fault/core.test.mjs
```

They cover request/response bounds, default broadcast refusal, fee overrides,
persist-before-forward ordering, a concurrent duplicate, restart after an
in-flight claim, accepted-only response dropping, upstream failure without retry,
and persistence failures. Live SOCKS/Tor transport, the build overlay and the
native test flows still require explicit operational verification.

# Trust Layer

Trust Layer investigates URLs and QR payloads using URL analysis, redirect tracing and isolated Chromium inspection. Mode C runs a disposable browser worker and a separate authenticated egress proxy; screenshots and findings are attached to the investigation case.

## Start the application

```powershell
npm install
npm start
```

## Enable Mode C

Mode C requires Docker Desktop using Linux containers and a running Docker daemon. The account running the Trust Layer backend must be allowed to access the Docker daemon. On Windows this normally means membership in `docker-users` and a sign-out/sign-in after the membership change. Do not run the application as an elevated administrator merely to work around a missing Docker permission.

Run the setup check from the repository root:

```powershell
.
scripts\setup_mode_c.ps1
```

The backend also verifies and builds the pinned worker image before each live run. It refuses inspection if Docker or the required network configuration is unavailable; it never falls back to a host browser or an HTTP-only result represented as a rendered inspection.

The worker runs as `pwuser`, with a read-only root filesystem, bounded memory/CPU/PIDs, ephemeral writable mounts, no `SYS_ADMIN`, and only the `SYS_CHROOT` capability Chromium needs. `worker/chromium-seccomp.json` is based on the [Moby default seccomp profile](https://github.com/moby/profiles/blob/main/seccomp/default.json) and permits Chromium's user-namespace syscalls. The worker sits on an internal Docker bridge with no direct internet route. A per-run authenticated proxy is the only outbound path and performs destination validation and DNS-pinned connections.

Mode C visits untrusted websites. Docker isolation reduces risk but does not make hostile content harmless. Each run is time-limited and its worker/proxy containers are removed when it ends. A valid PNG is required before the run can be reported as a completed rendered inspection; blocked targets and failed renders remain explicitly incomplete.

## Tests

Run unit and fixture tests with `npm test`. Docker integration checks are opt-in and require working Docker daemon access:

```powershell
$env:TRUSTLAYER_DOCKER_INTEGRATION = '1'
node --test tests/docker_proxy_connectivity.test.js
$env:TRUSTLAYER_DOCKER_API_INTEGRATION = '1'
node --test tests/mode_c_api_smoke.test.js
```

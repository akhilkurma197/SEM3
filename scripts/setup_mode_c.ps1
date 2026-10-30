$ErrorActionPreference = 'Stop'

try {
  docker info | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'docker info returned a failure status' }
} catch {
  throw 'Docker daemon is unavailable or this account cannot access it. Start Docker Desktop with Linux containers and check Docker daemon permissions.'
}

function Ensure-Network([string]$Name, [string]$Expected, [string[]]$CreateArgs) {
  $actual = & docker network inspect $Name --format '{{.Driver}} {{.Internal}}' 2>$null
  if ($LASTEXITCODE -ne 0) {
    & docker network create @CreateArgs $Name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create Docker network $Name." }
    $actual = & docker network inspect $Name --format '{{.Driver}} {{.Internal}}' 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Failed to inspect Docker network $Name after creation." }
  }
  $actual = ($actual | Out-String).Trim()
  if ($actual -ne $Expected) {
    throw "Docker network $Name has configuration '$actual'; expected '$Expected'. Refusing to modify an existing network."
  }
}

Ensure-Network 'trustlayer-isolated-net' 'bridge true' @('--driver', 'bridge', '--internal')
Ensure-Network 'trustlayer-egress-net' 'bridge false' @('--driver', 'bridge')
& docker build -t trustlayer-worker:latest -f worker/Dockerfile .
if ($LASTEXITCODE -ne 0) { throw 'Trust Layer worker image build failed.' }

Write-Host 'Mode C Docker runtime is ready. The backend will revalidate the networks and worker image before each live inspection.'

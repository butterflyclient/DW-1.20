param([switch]$Launch)
$ErrorActionPreference = 'Stop'
# Read-only readiness replaces the old local-server fixtures that issued fresh
# test sessions and depended on an obsolete source/deployment milestone.
& (Join-Path $PSScriptRoot 'launch-game.ps1') -ValidateOnly
if ($Launch) { & (Join-Path $PSScriptRoot 'launch-game.ps1') }

param([string]$NativeWriterSource = 'D:\mw124\mw120rproxy\iw8-zonetool\src')
$ErrorActionPreference = 'Stop'
$operatorBuild = Join-Path $PSScriptRoot 'build\custom-operator-model'
$operatorProject = Join-Path $operatorBuild 'cmake'
$operatorOutput = Join-Path $operatorBuild 'out'
New-Item -ItemType Directory -Force -Path $operatorProject | Out-Null
$operatorCmake = (Join-Path $PSScriptRoot 'custom-operator-model.cmake').Replace('\', '/')
@('cmake_minimum_required(VERSION 3.25)', 'project(custom_operator_model LANGUAGES C CXX)',
  ('include("' + $operatorCmake + '")')) |
    Set-Content -LiteralPath (Join-Path $operatorProject 'CMakeLists.txt')
& cmake -S $operatorProject -B $operatorOutput -G 'Visual Studio 18 2026' -A x64 "-DZONETOOL=$NativeWriterSource"
if ($LASTEXITCODE) { throw 'Custom operator writer configuration failed.' }
& cmake --build $operatorOutput --config Release -j 8
if ($LASTEXITCODE) { throw 'Custom operator writer compile failed.' }

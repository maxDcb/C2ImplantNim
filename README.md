# Exploration C2 HTTP Beacon in Nim

## Overview
This repository contains a small Nim implementation of an HTTP beacon compatible with the Exploration C2 framework available at [maxDcb/C2TeamServer](https://github.com/maxDcb/C2TeamServer). 

## Compilation
```
nim compile -d:ssl ./BeaconHttpLauncher.nim
nim compile -d:ssl ./BeaconGithubLauncher.nim
```

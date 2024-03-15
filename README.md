# Exploration C2 Implant in Nim

## What it is

Exploration is a rudimentary red team command and control frameworks.  
This repository contain the Implant in Nim (https://nim-lang.org) to target unix.
This development is in education exercises to tackle well know red teaming concepts.

## Compilation 

```
nim compile -d:ssl ./BeaconHttpLauncher.nim
nim compile -d:ssl ./BeaconGithubLauncher.nim
```

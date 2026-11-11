# AGENTS.md

## Only dns3lcli: CLI syntax
- All mandatory arguments must be positional arguments. All optional arguments must become flags.

## Only dns3ld:
- Check that config-example.yaml
  - contains all the config parameters that have been added, including a description,
  - does not contain any stale config parameters that are not used in the code anymore.

## Validation
- `golangci-lint run` (default settings) must pass
- `make unittest` must pass
- Check that README.md always is up-to-date with the code's behavior

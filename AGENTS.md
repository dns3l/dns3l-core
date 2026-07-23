# AGENTS.md

## Only dns3lcli: CLI syntax
- All mandatory arguments must be positional arguments. All optional arguments must become flags.

## Validation
- `golangci-lint run` (default settings) must pass
- `make unittest` must pass
- Check that README.md always is up-to-date with the code's behavior

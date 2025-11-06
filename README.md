[![Go Reference](https://pkg.go.dev/badge/go.iscode.ca/redact.svg)](https://pkg.go.dev/go.iscode.ca/redact)

# SYNOPSIS

redact [*options*] <file|directory|-> <...>

# DESCRIPTION

Redact secrets from files using
[gitleaks](https://github.com/gitleaks/gitleaks) rules.

# BUILDING

```
go install go.iscode.ca/redact/cmd/redact@latest
```

## Source

```
CGO_ENABLED=0 go build -trimpath -ldflags "-w" ./cmd/redact
```

# EXAMPLES

```
# redact files in-place
redact -i file.txt file.json file.yml

# redact files in-place found in current directory and subdirectories
# (exclude files using -S/--skip)
redact -i .

# from stdin
cat file | redact -

$ echo 'root:$6$d468dc01f1cd655d$1c0a188389f4db6399265080815ac488ea65c3295a18d2d7da3ce5e8ef082362adeedec9b69.9704d4d188:18515:0:99999:7:::' | \
 ./redact --rules examples/gitleaks.toml -
root:$6$**REDACTED**:18515:0:99999:7:::
```

# ENVIRONMENT VARIABLES

`REDACT_LOG_LEVEL`
: Sets default value for `--log-level`

`REDACT_REMOVE`
: Sets default value for `--remove`

`REDACT_RULES`
: Sets default value for `--rules`

`REDACT_SKIP`
: Sets default value for `-S`/`--skip`

`REDACT_SUBSTITUTE`
: Sets default value for `-s`/`--substitute`

# OPTIONS

-i/--inplace
: Redact the file in-place

--log-level *string*
: Set log level (default "error")

--remove *string*
: Redaction method: redact, mask, mask:**percentage** (default "redact")

--rules *string*
: Path to file containing gitleaks rules

-s *string*/--substitute *string*
: Text used to overwrite secrets (default `**REDACTED**`)

-S/--skip
: Skip glob matches in directories (default `.git .gitleaks.toml`)

## REDACTION METHODS

### redact

Replace the matched secret with the string provided by `--substitute`.

### mask

Overwrite the matched secret with the first character of the string
provided by `--substitute`.

`mask` can optionally leave a percentage of the match unmasked:

```
$ echo 'root:$6$d468dc01f1cd655d$1c0a188389f4db6399265080815ac488ea65c3295a18d2d7da3ce5e8ef082362adeedec9b69.9704d4d188:18515:0:99999:7:::' | \
 ./redact --remove=mask:10 --rules examples/gitleaks.toml -
root:$6$d468d*********************************************************************************************4d188:18515:0:99999:7:::
```

# ISSUES/TODO

Note: While efficient for small files, `redact` may not be ideal for
large files like logs because the entire file is read into memory.

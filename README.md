# SYNOPSIS

redact [*options*] <file|-> <...>

# DESCRIPTION

Redact secrets from files using
[gitleaks](https://github.com/gitleaks/gitleaks) rules.

# BUILDING

```
go install codeberg.org/msantos/redact/cmd/redact@latest
```

## Source

```
cd cmd/redact
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"
```

# EXAMPLES

```
# redact files in-place
redact -i file.txt file.json file.yml

# from stdin
cat file | redact -

$ echo 'root:$6$d468dc01f1cd655d$1c0a188389f4db6399265080815ac488ea65c3295a18d2d7da3ce5e8ef082362adeedec9b69.9704d4d188:18515:0:99999:7:::' | \
 cmd/redact/redact --rules examples/gitleaks.toml -
root:$6$**REDACTED**:18515:0:99999:7:::
```

# OPTIONS

-i/--inplace
: Redact the file in-place

--log-level *string*
: Set log level (default "error")

--remove *string*
Redaction method: redact, mask (default "redact")

--rules *string*
: Path to file containing gitleaks rules

-s *string*/--substitute *string*
: Text used to overwrite secrets (default `**REDACTED**`)

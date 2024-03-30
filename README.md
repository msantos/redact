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
```

# OPTIONS

--i/--inplace
: Redact the file in-place

--log-level *string*
: Set log level (default "error")

--mask
: Mask secret

--rules *string*
: Path to file containing gitleaks rules

-s *string*
: Text used to overwrite secrets (default `**REDACTED**`)

--substitute *string*
: Text used to overwrite secrets (default `**REDACTED**`)

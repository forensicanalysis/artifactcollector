# Artifact definition format and style guide

## Summary

This guide contains a description of the forensics artifacts definitions. The
artifacts definitions are [YAML](http://www.yaml.org/spec/1.2/spec.html)-based.
The format is currently still under development and is likely to undergo some
change. One of the goals of this guide is to ensure consistency and readability
of the artifacts definitions.

## Revision history

| Version  | Author    | Date           | Comments                                                                            |
|----------|-----------|----------------|-------------------------------------------------------------------------------------|
| 0.0.1    | G. Castle | November 2014  | Initial version.                                                                    |
| 0.0.2    | G. Castle | December 2014  | Minor format changes.                                                               |
| 0.0.3    | J.B. Metz | April 2015     | Merged style guide and artifact definitions wiki page.                              |
| 0.0.3    | J.B. Metz | September 2015 | Additional label.                                                                   |
| 0.0.4    | J.B. Metz | July 2016      | Added information about a naming convention.                                        |
| 0.0.5    | J.B. Metz | February 2019  | Removed returned_types as keyword and format changes.                               |
| 0.0.6-ce | J. Plum   | October 2019   | Add information about the knowledge base, directory sources, expansion and globbing |
| 0.0.7-ce | J. Plum   | October 2024   | Deprecate labels                                                                    |

## Background

The first version of the artifact definitions originated from the
[GRR project](https://github.com/google/grr), where it is used to describe and
quickly collect data of interest, e.g. specific files or Windows Registry keys.
The goal of the format is to provide a way to describe the majority of forensic
artifacts in a language that is readable by humans and machines.

The format is designed to be simple and straight forward, so that a digital
forensic analyst is able to quickly write artifact definitions during an
investigation without having to rely on complex standards or tooling.

The format is intended to describe forensically-relevant data on a machine,
while being tool agnostic. In particular, we intentionally avoided adding
IOC-like logic, or describing how the data should be collected since this
varies between tools.

### Terminology

The term artifact (or artefact) is widely used within computer (or digital)
forensics, though there is no official definition of this term.

The definition closest to the meaning of the word within computer forensics is
that of the word artifact within
[archaeology](http://en.wikipedia.org/wiki/Artifact_(archaeology)). The term
should not be confused with the word artifact used within
[software development](http://en.wikipedia.org/wiki/Artifact_(software_development)).

If archaeology defines an artifact as:

```
something made or given shape by man, such as a tool or
a work of art, esp an object of archaeological interest
```

The definition of artifact within computer forensics could be:

```
An object of digital archaeological interest.
```

Where digital archaeology roughly refers to computer forensics without the
forensic (legal) context.

### Knowledge Base

The knowledge base is a data store that is used for storing entries about
the host, users and other system properties. Every entry maps a key to a list
of values e.g.

```json
{
  "users.username": [
    "root",
    "bob"
  ],
  "users.homedir": [
    "/root",
    "/home/bob"
  ]
}
```

It is filled via the `provides` attribute of sources and
can be used in artifact conditions (*deprecated*) and in
[parameter expansion](#parameter-expansion-and-globs).

## The artifact definition

The best way to show what an artifact definition is, is by example. The
following example is the artifact definition for the Windows EVTX System Event
Logs.

```yaml
name: WindowsSystemEventLogEvtx
doc: Windows System Event log for Vista or later systems.
sources:
  - type: FILE
    attributes: { paths: [ '%%environ_systemroot%%\System32\winevt\Logs\System.evtx' ] }
supported_os: [ Windows ]
```

The artifact definition can have the following values:

| Key            | Description                                                                                                                                                                                                                                                                  |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| name           | The name. An unique string that identifies the artifact definition. Also see section: [Name](#Name).                                                                                                                                                                         |
| doc            | The description (or documentation). A human readable string that describes the artifact definition. *Style note*: Typically one line description of the artifact, mentioning important caveats. If more description is necessary, use the [Long docs form](#long-docs-form). |
| sources        | A list of source definitions. See section: [sources](#sources).                                                                                                                                                                                                              |
| supported_os   | Optional list that indicates which operating systems the artifact definition applies to. See section: [Supported operating system](#supported-operating-system).                                                                                                             |
| urls           | Optional list of URLs with more contextual information. Ideally the artifact definition links to an article that discusses the artificat in more depth.                                                                                                                      |
| ~~labels~~     | **Deprecated** This key is ignored.                                                                                                                                                                                                                                          |
| ~~conditions~~ | **Deprecated** This key is ignored.                                                                                                                                                                                                                                          |
| ~~provides~~   | **Deprecated** This key is ignored.                                                                                                                                                                                                                                          |

### Name

*Style note*: The name of an artifact definition should be in CamelCase name
without spaces.

Naming convention for artifact definition names:

* Prefix platform specific artifact definitions with the name of the operating system using "Linux", "MacOS" or "
  Windows"
* If not platform specific:
    * prefix with the application name, for example "ChromeHistory".
    * prefix with the name of the subsystem, for example "WMIComputerSystemProduct".

*Style note*: If the sole source of the artifact definition for example are
files use "BrowserHistoryFiles" instead of "BrowserHistory" to reduce ambiguity.

### Long docs form

Multi-line documentation should use the YAML Literal Style as indicated by the |
character.

```yaml
doc: |
  The Windows run keys.

  Note users.sid will currently only expand to SIDs with profiles on the 
  system, not all SIDs.
```

*Style note*: the short description (first line) and the longer portion are
separated by an empty line.

*Style note*: explicit newlines (\n) should not be used.

## Sources

Every source definition starts with a `type` followed by arguments e.g.

```yaml
sources:
  - type: COMMAND
    attributes:
      args: [ -qa ]
      cmd: /bin/rpm
```

```yaml
sources:
  - type: FILE
    attributes:
      paths:
        - /root/.bashrc
        - /root/.cshrc
        - /root/.ksh
        - /root/.logout
        - /root/.profile
        - /root/.tcsh
        - /root/.zlogin
        - /root/.zlogout
        - /root/.zprofile
        - /root/.zprofile
```

*Style note*: where sources take a single argument with a single value, the
one-line {} form should be used to save on line breaks as below:

```yaml
- type: FILE
  attributes: { paths: [ '%%environ_systemroot%%\System32\winevt\Logs\System.evtx' ] }
```

| Key            | Description                                                                                                                                        |
|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| attributes     | A dictionary of keyword attributes specific to the type of source definition.                                                                      |
| type           | The source type.                                                                                                                                   |
| provides       | Optional list of dictonaries that describe knowledge base entries that this artifact can supply. See section: [Source provides](#source-provides). |
| supported_os   | Optional list that indicates which operating systems the artifact definition applies to.                                                           |
| ~~conditions~~ | **Deprecated** This key is ignored.                                                                                                                |

### Source types

Currently, the following different source types are defined:

| Value          | Description                                                                               |
|----------------|-------------------------------------------------------------------------------------------|
| ARTIFACT_GROUP | A source that consists of a group of other artifacts.                                     |
| COMMAND        | A source that consists of the output of a command.                                        |
| DIRECTORY      | A source that consists of the file listing of a directories.                              |
| FILE           | A source that consists of the contents of files.                                          |
| PATH           | A source that consists of a list of paths.                                                |
| REGISTRY_KEY   | A source that consists of the contents of Windows Registry keys.                          |
| REGISTRY_VALUE | A source that consists of the contents of Windows Registry values.                        |
| WMI            | A source that consists of the output of a Windows Management Instrumentation (WMI) query. |

### Source provides

A source provide defines a knowledge base entry that can be created using this source e.g.

```yaml
sources:
  - type: PATH
    attributes: { paths: [ '/Users/*' ] }
    provides:
      - key: users.username
        regex: '.*/(.*)'
```

```yaml
sources:
  - type: WMI
    attributes: { query: SELECT * FROM Win32_UserAccount WHERE name='%%users.username%%' }
    provides:
      - key: users.userdomain
        wmi_key: Domain
```

```yaml
sources:
  - type: FILE
    attributes: { paths: [ '/etc/passwd' ] }
    provides:
      - key: users.username
        regex: '(.*?):.*'
      - key: users.homedir
        regex: '.*:(.*?):.*'
```

| Key     | Description                                                                                                    |
|---------|----------------------------------------------------------------------------------------------------------------|
| key     | Defines the knowledge base key that is provided.                                                               |
| wmi_key | Required for provides in WMI sources, disallowed otherwise. WMI object key to select the provided value.       |
| regex   | Optional regular expression to filter the provided data. The first capturing group defines the provided value. |

Provided values are dependent on the source type as follows:

| Type           | Added entries to knowledge base          |
|----------------|------------------------------------------|
| COMMAND        | The lines of the stdout of the command.  |
| FILE           | The lines of the file content.           |
| PATH           | The defined paths.                       |
| REGISTRY_KEY   | The key paths.                           |
| REGISTRY_VALUE | The registry values.                     |
| WMI            | The values selected using the `wmi_key`. |

Definition of type ARTIFACT_GROUP or DIRECTORY must not have a `provides` attribute.

### Artifact group source

The artifact group source is a source that consists of a group of other
artifacts e.g.

```yaml
- type: ARTIFACT_GROUP
  attributes:
    names: [ WindowsRunKeys, WindowsServices ]
```

Where `attributes` can contain the following values:

| Value | Description                                                                                                                                                        |
|-------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| names | A list of artifact definition names that make up this "composite" artifact. This can also be used to group multiple artifact definitions into one for convenience. |

### Command source

The command source is a source that consists of the output of a command e.g.

```yaml
- type: COMMAND
  attributes:
    args: [ -qa ]
    cmd: /bin/rpm
```

Where `attributes` can contain the following values:

| Value | Description                                                                                                                                          |
|-------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| args  | A list arguments to pass to the command.                                                                                                             |
| cmd   | The path of the command. The path can either be relative or absolute. Handling of relative paths depends on the application processing the artifact. |

### Directory source

The directory source is a source that consists of a file listing of directory contents e.g.

```yaml
- type: DIRECTORY
  attributes:
    paths: [ '%%users.userprofile%%\Downloads\*' ]
    separator: '\'
```

Where `attributes` can contain the following values:

| Value     | Description                                                                                                                                                                                                                               |
|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| paths     | A list of file paths that can potentially be collected. These paths should be absolute. The paths can use parameter expansion e.g. `%%environ_systemroot%%`. See section: [Parameter expansion and globs](#parameter-expansion-and-globs) |
| separator | Optional path separator e.g. '\' for Windows systems.                                                                                                                                                                                     |

### File source

The file source is a source that consists of the binary contents of files e.g.

```yaml
- type: FILE
  attributes:
    paths: [ '%%environ_systemroot%%\System32\winevt\Logs\System.evtx' ]
```

Where `attributes` can contain the following values:

| Value     | Description                                                                                                                                                                                                                               |
|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| paths     | A list of file paths that can potentially be collected. These paths should be absolute. The paths can use parameter expansion e.g. `%%environ_systemroot%%`. See section: [Parameter expansion and globs](#parameter-expansion-and-globs) |
| separator | Optional path separator e.g. '\' for Windows systems.                                                                                                                                                                                     |

### Path source

The path source is a source that consists of a list of paths e.g.

```yaml
- type: PATH
  attributes:
    paths: [ '\Program Files' ]
    separator: '\'
```

Where `attributes` can contain the following values:

| Value     | Description                                                                                                                                                                                                                         |
|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| paths     | A list of file paths that can potentially be collected. These paths can should be absolute. The paths can use parameter expansion e.g. `%%environ_systemroot%%`. See section: [Parameter expansion and globs](#parameter-expansion) |
| separator | Optional path separator e.g. '\' for Windows systems.                                                                                                                                                                               |

### Windows Registry key source

The Windows Registry key source is a source that consists of a key path and all
registry values of a Windows Registry key. Subkeys are not part of this artifact.

Example:

```yaml
sources:
  - type: REGISTRY_KEY
    attributes:
      keys:
        - 'HKEY_USERS\%%users.sid%%\Software\Microsoft\Internet Explorer\TypedURLs\*'
```

Where `attributes` can contain the following values:

| Value | Description                                                                                                                                                                                            |
|-------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| keys  | A list of Windows Registry key paths that can potentially be collected. The paths can use parameter expansion e.g. `%%users.sid%%`. See section: [Parameter expansion and globs](#parameter-expansion) |

### Windows Registry value source

The Windows Registry value source is a source that consists of the contents of defined
Windows registry values e.g.

```yaml
- type: REGISTRY_VALUE
  attributes:
    key_value_pairs:
      - { key: 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\WindowsUpdate', value: 'CISCNF4654' }
```

Where `attributes` can contain the following values:

| Value           | Description                                                                                                                                                                                                               |
|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| key_value_pairs | A list of Windows Registry key paths and value names that can potentially be collected. The key path can use parameter expansion e.g. `%%users.sid%%`. See section: [Parameter expansion and globs](#parameter-expansion) |

### Windows Management Instrumentation (WMI) query source

The Windows Management Instrumentation (WMI) query source is a source that
consists of the output of a Windows Management Instrumentation (WMI) query e.g.

```yaml
- type: WMI
  attributes:
    query: SELECT * FROM Win32_UserAccount WHERE name='%%users.username%%'
```

Where `attributes` can contain the following values:

| Value       | Description                                                                                                                                                                                       |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| query       | The Windows Management Instrumentation (WMI) query. The query can use parameter expansion e.g. `%%users.username%%`. See section: [Parameter expansion and globs](#parameter-expansion-and-globs) |
| base_object | Optional WMI base object e.g. `winmgmts:\root\SecurityCenter2`                                                                                                                                    |

## Supported operating system

Since operating system (OS) conditions are a very common constraint, this has
been provided as a separate option `supported_os` to simplify syntax. For
supported_os no quotes are required. The currently supported operating systems
are:

* Darwin (also used for Mac OS X)
* Linux
* Windows

```yaml
supported_os: [ Darwin, Linux, Windows ]
```

## Style notes

### Artifact definition YAML files

Artifact definition YAML filenames should be of the form:
....
$FILENAME.yaml
....

Where $FILENAME is name of the file e.g. windows.yaml.

Each definition file should have a comment at the top of the file with a
one-line summary describing the type of artifact definitions contained in the
file e.g.

```yaml
# Windows specific artifacts.
```

### Lists

Generally use the short [] format for single-item lists that fit inside 80
characters to save on unnecessary line breaks:

```yaml
supported_os: [ Windows ]
```

and the bulleted list form for multi-item lists or long lines:

```yaml
paths:
  - 'HKEY_USERS\%%users.sid%%\Software\Microsoft\Windows\CurrentVersion\Run\*'
  - 'HKEY_USERS\%%users.sid%%\Software\Microsoft\Windows\CurrentVersion\RunOnce\*'
  - 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\*'
  - 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce\*'
  - 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\*'
```

### Quotes

Quotes should not be used for doc strings, artifact names, and simple lists
like labels and supported_os.

Paths and URLs should use single quotes to avoid the need for manual escaping.

```yaml
paths: [ '%%environ_temp%%\*.exe' ]
```

Double quotes should be used where escaping causes problems, such as
regular expressions:

```yaml
content_regex_list: [ "^%%users.username%%:[^:]*\n" ]
```

### Minimize the number of definitions by using multiple sources

To minimize the number of artifacts in the list, combine them using the
supported_os and conditions attributes where it makes sense. e.g. rather than
having FirefoxHistoryWindows, FirefoxHistoryLinux, FirefoxHistoryDarwin, do:

```yaml
name: FirefoxHistory
doc: Firefox places.sqlite files.
sources:
  - type: FILE
    attributes:
      paths:
        - %%users.localappdata%%\Mozilla\Firefox\Profiles\*\places.sqlite
        - %%users.appdata%%\Mozilla\Firefox\Profiles\*\places.sqlite
    supported_os: [ Windows ]
  - type: FILE
    attributes:
      paths: [ %%users.homedir%%/Library/Application Support/Firefox/Profiles/*/places.sqlite ]
    supported_os: [ Darwin ]
  - type: FILE
    attributes:
      paths: [ '%%users.homedir%%/.mozilla/firefox/*/places.sqlite' ]
    supported_os: [ Linux ]
supported_os: [ Windows, Linux, Darwin ]
```

## Parameter expansion and globs

### Parameter expansion

Path, keys, key and query attributes can contain parameter expansion and
globing. This allows for flexible creation of artifact locations.

Parameter expansions values are enclosed by double percent symbols e.g.
`%%environ_systemroot%%`. The parameter expansion value can be replaced by the
corresponding value from the [knowledge base](#knowledge-base).

For every expansion that is used in an artifact, there should be another artifact
that `provides` this expansion in one of its sources. Implementations may choose
to precompute parameter values from sources outside of these definitions.

### Parameter Globs

Parameters can also contain regular glob elements (`**`, or `*`).
For example, having files `foo`, `bar`, `baz` glob expansion of `ba*`
will yield `bar` and `baz`. A recursive component (specified as `**`)
matches any directory tree up to some specified depth (3 by default).
`**` does not match the current directory.
The search depth can optionally be specified by appending a number, e.g.
`**9` will match up to 9 levels of a directory hierarchy.

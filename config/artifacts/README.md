## Artifact Definitions

The artifactcollector uses yaml files to define forensic artifacts it can collect.

The yaml files are based on the [ForensicArtifacts/artifacts](https://github.com/ForensicArtifacts/artifacts)
repository, but with the following major changes:

- `provides` on source level are added to enable extraction of parameters
- All source types are distinctly defined, including the `DIRECTORY` type.
- Parameter expansion and globing is defined, including `**`.
- Inconsistent trailing `\*` in REGISTRY_KEYs are removed.

The [Style Guide](style_guide.md) describes the full specification of the artifact definitions 
how they are used in the artifactcollector.

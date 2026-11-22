# Model artifacts

These are the exact checkpoints used by the cascade. The weights and large
tokenizers are not committed: `edgegate fetch-models` downloads them from the
pinned upstream revisions below and checks every size and SHA256 against
`manifest.json`. Small configuration files are committed as they are.

| Model | Artifact | Upstream revision |
|---|---|---|
| Basal Omni Pico | `basal/basal-omni-pico-Q8_0.gguf` | `Remek/basal-omni-pico-GGUF@f13a8cd528e446dc705131373371e0755e3ad1cf` |
| Laya English classic | `laya/model.safetensors` | `convaiinnovations/laya@fd4f9dbcf4fde222fd43174bdd4c3b08b789e4e1` |
| Kev 0.8B | `kev/Kev-0.8B-Q8_0.gguf` | `ggml-org/Kev-0.8B-GGUF@9231cb757e3320120077e42e52371971968f008d` |

The manifest records file sizes, SHA256 hashes and immutable source URLs. The
tokenizers and all local model configuration needed by the runtimes are included.
Unused BF16, multilingual and typed-decisions variants are not required by this
calibrated policy. Do not substitute them without recalibration.

All three upstream model cards declare Apache-2.0. Original cards are preserved
as `README.upstream.md` in each model directory; the license text is included as
`LICENSE-APACHE-2.0.txt`. The fetched weights, tokenizers and committed configuration
files are unmodified. The manifest and deployment documentation were added here.

```sh
make cascade50-models          # in Docker, ~2.5 GB, skips files that already match
# or without Docker:
make edgegate && ./bin/edgegate fetch-models && ./bin/edgegate verify-models
```

See [the complete run instructions](../deploy/cascade50/README.md).

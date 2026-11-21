---
license: apache-2.0
language:
- pl
- en
base_model: Remek/basal-omni-pico
library_name: gguf
pipeline_tag: text-generation
tags:
- typed-decisions
- decision-making
- classification
- calibration
- polish
- gguf
- llama.cpp
- edge
- decision-model
---

# basal-omni-pico-GGUF

[![GitHub](https://img.shields.io/badge/GitHub-rkinas%2Fbasal%20%E2%80%94%20inference%20engine-black?logo=github)](https://github.com/rkinas/basal)
[![Website](https://img.shields.io/badge/web-basal.si5.pl-0a7d5a)](https://basal.si5.pl/)

A Q8_0 GGUF file of [basal-omni-pico](https://huggingface.co/Remek/basal-omni-pico) (0.8B, built on Qwen3.5-0.8B-Base) for
llama.cpp, on the CPU or on a GPU. Same model and the same typed-decision API through `basal-serve`: it reads a state
and answers typed questions about it with a probability for each allowed option, in one prefill, without generating
text. Results, limitations and training are on the [main model card](https://huggingface.co/Remek/basal-omni-pico).

## Measured against the bf16 model

**Agreement** is the share of decisions where the file picks the same option as the bf16 model served as released
(basal 2.3.2, `--mode eager`, bf16, one H100), on 1,700 items of our development sets (one option order):

| where | items | agreement on the top answer [95% interval] | largest probability difference | accuracy: GGUF / bf16 |
|---|---|---|---|---|
| one H100 (CUDA) | 1,700 | 99.24% [98.70, 99.55] | 0.30 | 0.721 / 0.719 |
| CPU (Xeon Platinum 8460Y+, 16 or 32 threads) | 1,700 | 99.29% [98.77, 99.60] | 0.21 | 0.718 / 0.719 |

- The differences are near-ties. No probability was non-finite on either device.
- **Automation** with this folder's `CALIBRATION.gguf.json` (fitted on Q8_0 readouts with `--mode gguf`, one option
  order, our calibration set; evaluated on a frozen test split of 8,560 decisions): at `max_error` 1%, 35.4% of decisions are decided
  automatically (observed error 0.96%); at 5%, 58.5% (4.51%). ECE after the temperature: choice 0.009, yes/no 0.013,
  score 0.060. The bf16 model's own file gives 35.0% (0.93%) and 58.2% (4.38%) on the same split.
- These thresholds hold on our held-out test split. On Werdykt, an out-of-domain benchmark, the bf16 model served with
  its own calibration is overconfident (mean confidence 0.80 against accuracy 0.66, ECE 0.138) and misses the 5%
  target (33.9% automated, observed error 6.3%). Outside our domains, refit the thresholds on your own labelled cases
  (`basal-calibrate`) before you automate.
- The file is a port of the same model, not a new model; its benchmark results are on the
  [main model card](https://huggingface.co/Remek/basal-omni-pico). This file is not scored separately on them.

## Use

Install basal 2.5.0 with the `gguf` extra (llama-cpp-python 0.3.36 or newer), then serve the file:

```bash
# On a Mac, the native arm64 Python in place of the next line (uname -m prints arm64, not x86_64 under Rosetta):
#   (made earlier under Rosetta? if `grep -l x86_64 ~/basal-env/lib/python3*/site-packages/*.dist-info/WHEEL` lists any, --clear once in place of --allow-existing)
#   uv python install cpython-3.12-macos-aarch64-none
#   uv venv --python cpython-3.12-macos-aarch64-none --allow-existing ~/basal-env && source ~/basal-env/bin/activate
uv venv --python 3.12 --allow-existing ~/basal-env && source ~/basal-env/bin/activate
uv pip install torch==2.11.0 --index-url https://download.pytorch.org/whl/cpu
uv pip install "basal[gguf] @ https://github.com/rkinas/basal/archive/refs/tags/v2.8.1.tar.gz"
hf download Remek/basal-omni-pico-GGUF --local-dir basal-omni-pico-GGUF
basal-serve --model ./basal-omni-pico-GGUF --mode gguf --gguf basal-omni-pico-GGUF/basal-omni-pico-Q8_0.gguf --port 8000
```

Then ask questions exactly as with [basal-omni-pico](https://huggingface.co/Remek/basal-omni-pico):

```bash
curl -s localhost:8000/v1/systemone -H 'content-type: application/json' -d '{
  "state": "Klient: od wczoraj nie mogę zalogować się do bankowości internetowej, system pokazuje błąd hasła.",
  "questions": {
    "dept":   {"type": "choice", "instructions": "Do którego działu skierować zgłoszenie?",
               "criteria": {"cards": "Reklamacje kart", "online": "Wsparcie bankowości elektronicznej", "loans": "Kredyty"}},
    "urgent": {"type": "noul", "instructions": "Czy klient nie może korzystać z usługi?"}}}'
```

The answer (Q8_0 on 16 CPU threads, basal 2.3.2, shortened):

```json
{"answers": {
  "dept":   {"type": "choice", "choice": "online", "probabilities": {"cards": 0.0008, "online": 0.9984, "loans": 0.0008},
             "confidence": 0.9984},
  "urgent": {"type": "noul", "noul": 0.768, "probabilities": {"true": 0.768, "false": 0.232}, "confidence": 0.768}}}
```

The bf16 model gives 0.9983 and 0.762 for the same request (one H100, installed as on its card).

- llama-cpp-python from PyPI builds for the CPU. On NVIDIA, build it with CUDA (see the engine's docs/GGUF.md); on a
  Mac it uses Metal.
- **On a Mac:** `--mode gguf` with this repository, or `--mode mlx` with [basal-omni-pico](https://huggingface.co/Remek/basal-omni-pico) (basal >= 2.5.0); `--mode mps` is refused for this model.
- **basal 2.3.2 or later.** Qwen3.5 keeps a recurrent state per sequence in its Gated DeltaNet layers; basal 2.3.2
  decodes one prompt at a time for such models. Earlier versions returned non-finite probabilities on the CPU.
- **Calibration:** `--mode gguf` loads `CALIBRATION.gguf.json`, fitted on this file; `CALIBRATION.json` is the bf16
  model's file. Both are fitted for one option order (the default). You can refit on your own labelled data with
  `basal-calibrate`.
- **Speed** (basal 2.3.2, one request at a time): the request above (two questions, 232 tokens) takes 0.46-0.51 s on
  16 CPU threads of a Xeon Platinum 8460Y+ and 0.09 s on one H100; a five-question request 1.4 s on the CPU. Our
  development items took about 0.9 s per decision on the CPU. On one H100 the Q8_0 file answers one short question in
  56.5 ms (p50) and 18.1 decisions/s with 16 requests in flight (measured on one of the two checkpoints averaged into
  this model).

## How it was made

- `convert_hf_to_gguf.py` of the llama.cpp vendored in llama-cpp-python 0.3.36, on the released bf16 weights, with
  `--no-mtp` (the release has no multi-token-prediction layer), to bf16; then llama.cpp's quantizer (the same library)
  from bf16 to Q8_0. llama.cpp architecture `qwen35`.
- `CALIBRATION.gguf.json`: the bf16 model's method and splits on this file's readouts (`--mode gguf` on one H100, one
  option order): per-type and per-bucket temperatures and certified thresholds for 1% and 5% error.

## Files

- `basal-omni-pico-Q8_0.gguf`: the GGUF file (812 MB; 320 tensors: the 133 norm and Gated DeltaNet `a` / `dt` / conv tensors
  stay F32, the other 187 are Q8_0, including the token embedding, which is also the tied output head); sha256
  `f8ef7349c730fca055c01255cdaa5c7b94848285d634b61996bbde5835437354`
- Tokenizer, `chat_template.jinja`, `generation_config.json`, `basal.json`: as in the bf16 model (the basal server
  renders the prompt with them).
- `CALIBRATION.gguf.json`, `CALIBRATION.json`: the calibration fitted on this file, and the bf16 model's.
- **LM Studio:** `basal-omni-pico-Q8_0-decision.gguf` is the file above with basal's decision metadata added (weights unchanged). LM Studio 0.4.26 or newer (beta channel at the time of writing; llama.cpp engine 2.65.1+, not the MLX engine) serves it as a decision model on `/v1/systemone` and `/v1/decisions`: choice, yes/no and score, up to 26 options, temperatures from `CALIBRATION.gguf.json`. LM Studio ends a request after 30 s, so split very long documents.
  - With basal 2.5.0 you can add the same metadata to a GGUF file yourself (a file of this repository, downloaded, or your own quantisation; the tensors are not touched): `basal-export-gguf Remek/basal-omni-pico-GGUF lmstudio/basal-omni-pico-Q8_0.gguf --gguf basal-omni-pico-Q8_0.gguf --systemone`.
- `SHA256SUMS`: the sha256 of every file above (check with `sha256sum -c SHA256SUMS`)

## License

Apache-2.0, as [basal-omni-pico](https://huggingface.co/Remek/basal-omni-pico); built on
[Qwen/Qwen3.5-0.8B-Base](https://huggingface.co/Qwen/Qwen3.5-0.8B-Base) (Apache-2.0) by the Qwen team.

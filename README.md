SPDAgent Quick Guide
====================

Prerequisites
- Install IDA (with Python support) and ensure `idat` (or headless binary) works in CLI.
- Install/prepare the Diaphora plugin and make sure `diaphora.py` and its dependencies are available.
- Use Python 3.11.8 (recommended). Install project dependencies (`requirements.txt`).

Required configuration (replace placeholders with your values)
- `config/general_config.yaml`
  - `ida`: /path/to/ida/idat
  - `diaphora_py`: /path/to/diaphora/diaphora.py
  - `diaphora`: /path/to/diaphora
  - `scripts_dir`: /path/to/SPDAgent/pseudo_diff_gen
  - If you want tmpfs, keep `tmpfs_dir: /dev/shm`; otherwise set it to an empty string.
- `config/llm_config.yaml`
  - `OPENAI_API_KEY`: YOUR_API_KEY
  - `OPENAI_API_BASE`: https://api.your-provider.com/v1 (or your model endpoint)
  - `prompt_path` entries: set each to your actual path, e.g. `/path/to/SPDAgent/LLM_query/prompt/...`

Run a quick sample
- Run:
  ```bash
  python SPD.py --bin_dir test_bin/
  ```
- Outputs will be written under `storage/result/...`, including diffs and reports.

Notes
- For custom datasets, add paths under `datasets` in `config/general_config.yaml`.

Dataset availability
--------------------

The SPD-BIN dataset is approximately 100 GB in size (uncompressed).
To request access to the dataset, please contact [yangfr23@tsinghua.org.cn](mailto:yangfr23@tsinghua.org.cn).

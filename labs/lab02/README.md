# Laboratory Work #2

Student: Перестюк Назарій Романович (КБ-205)  
Variant 2: **File Integrity Monitor**

## Tasks

Task 1 implements an OOP user-account model: a salted PBKDF2 password hash,
email validation, administrator permissions, UTC sessions, and password-free
audit records.

Task 2 implements a File Integrity Monitor (FIM). It recursively scans files,
stores SHA-256, size, and modification time in a JSON baseline, then detects
integrity changes.

## Project data

```
labs/lab02/
├── main.py
├── task1.py
├── task2.py
└── data/
    └── data_v02/
        ├── baseline.json
        └── monitored/
            ├── README.txt
            ├── config/app.conf
            ├── config/firewall.conf
            ├── new/agent.conf
            └── scripts/backup.sh
```

## Installation

```bash
pip install -r requirements.txt
```

## Commands

Run the Task 1 demonstration:

```bash
python -m labs.lab02.main demo
```

Generate a baseline for the existing monitored directory:

```bash
python -m labs.lab02.main analyze --dir labs/lab02/data/data_v02/monitored --baseline labs/lab02/data/data_v02/baseline.json --mode generate --log-file labs/lab02/data/data_v02/fim_audit.log
```

Check the directory against its baseline:

```bash
python -m labs.lab02.main analyze --dir labs/lab02/data/data_v02/monitored --baseline labs/lab02/data/data_v02/baseline.json --mode check --log-file labs/lab02/data/data_v02/fim_audit.log
```

Parameters: `--dir` is the scanned directory; `--baseline` is the JSON state
file; `--mode` is `generate` or `check`; and `--log-file` optionally stores the
audit log. If the baseline or log is placed inside the monitored directory, it
is excluded from scanning.

`CREATED` means a file is absent from the baseline but present now. `DELETED`
means it was in the baseline but is absent now. `MODIFIED` means its SHA-256
hash differs. Missing directories, non-directory paths, missing baselines,
invalid JSON, and normal file-access errors are reported with understandable
messages instead of a traceback.

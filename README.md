# AutoPatcher
AutoPatcher: Automatic Root-Cause-Analysis Guided Program Repair via Large Language Models

## Structure
The structure of the repository is as follows:

```bash
.
├── autopatcher.py # Main script for calling the fine-tuned model (CodeT5) for patching
├── autopatch_results # Directory for storing the patched files
│   └── vuln_fix_pairs.csv # CSV file containing the vulnerability and the corresponding patch
├── data ## Directory for storing the data
│   ├── demo_conti.csv # CSV file containing some CVEs for demonstration, feeding into the autopatcher
│   └── demo_cve.csv # also a CSV file containing some CVEs for demonstration, feeding into the autopatcher
├── get_functions.py # Script for extracting functions from the C/C++ code by using tree-sitter
├── LICENSE
├── models ## Directory for storing the fine-tuned model (CodeT5)
│   └── model.bin # Fine-tuned model for patching
├── parse_vuln_loc.py # Script for parsing the location of the vulnerability in the C/C++ code according to the Root Cause Analysis (RCA) tool (Aurora now)
├── rca ## Directory for storing the RCA reports and the source code of the target project
│   ├── mruby # Example project
│   ├── rca_reports # Directory for storing the RCA reports
│   └── test_parser.c # Example C file for testing the functionality of the get_functions.py script
├── README.md
└── requirements.txt # Required packages for running the autopatcher
```

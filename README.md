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

## Environment Setup



To run the AutoPatcher, you need to install the required packages by running the following command:

### Install a virtual environment
```bash
python3 -m venv .venv
```

### Activate the virtual environment
```bash
source .venv/bin/activate
```

### Install the required packages

```bash
python3 -m pip install -r requirements.txt
```

#### Torch Installation

The torch lib within the requirements.txt is a CPU version. If it is not working or there is a GPU available, you can install the GPU version of torch by following the instructions [here](https://pytorch.org/get-started/locally/). 

### Download the fine-tuned model file

You can download the fine-tuned model file `model.bin` from [Google Drive](https://drive.google.com/file/d/1odETLrot-tCNxUoDJsyLuGjGRwsICeZ9/view?usp=sharing) and save it in the `models` directory.


### Run the AutoPatcher

#### Example usage

```bash
python autopatcher.py --output_dir ./models --num_beams 1
```

#### Options

> Note that the `--num_beams` parameter is used to control the number of beams for the beam search decoding. The default value is 1. 
You can change it to a larger value to generate more patches if needed. But it is recommended to keep it as 1 for the best performance if you use the CPU for running the AutoPatcher. 


## Demo for AutoPatcher

To demonstrate the functionality of the AutoPatcher, we provide a demo using the CVEs ([CVE-2017-16527](https://nvd.nist.gov/vuln/detail/CVE-2017-16527) and [CVE-2018-10191]()). The demo consists of the following steps:


### CVE-2017-16527

`sound/usb/mixer.c` in the Linux kernel before 4.13.8 allows local users to cause a denial of service (snd_usb_mixer_interrupt use-after-free and system crash) or possibly have unspecified other impact via a crafted USB device.


By feeding the vulnerable code snippet into the AutoPatcher, it generates the following patch:

```bash
<S2SV_ModStart>mixer ) { snd_usb_mixer_disconnect ( mixer ) ;
```
to kill pending URBs and free the mixer instance before the mixer instance is freed, which is consistent with the real patch for the CVE-2017-16527 at [here](https://github.com/torvalds/linux/commit/124751d5e63c823092060074bd0abaae61aaa9c4). 

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
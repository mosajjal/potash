# Potash Malware Search Engine

Potash Malware Search Engine is a command-line tool that utilizes TLSH and vptree to provide a proximity search engine for malware. The tool ingests the abuse.ch input CSV file and generates a vptree based on the TLSH values. The vptree is then serialized and saved as a GOB file for future use.

The tool can run in two modes: `interactive` and `once`. In the interactive mode, the tool prompts the user to enter the TLSH but doesn't exit after printing the 10 closes SHA256 hashes. In the `once` mode, the tool takes the file path or TLSH hash as a command-line argument and returns the 10 closest malware SHA256 hashes.

## Requirements
- Go 1.19 or later


## Installation
To get started, first, you need to clone the repository by running the following command in your terminal:
`git clone https://github.com/mosajjal/potash.git`

Once the cloning is complete, navigate to the project directory using the command:
`cd potash`

After that, build the binary using the following command:
`go build ./...`

Finally, to run the tool, enter the command:
`./potash`

## Usage

```bash
potash consumes the abuse.ch malware export CSV file, generates a trie based on
                the TLSH hashes and then provides a CLI to query the trie for similar hashes

Usage:
  potash [command]

Available Commands:
  completion     Generate the autocompletion script for the specified shell
  generate       generate a new tree
  help           Help about any command
  runinteractive run interactive
  runonce        run once

Flags:
  -h, --help   help for potash

Use "potash [command] --help" for more information about a command.
```

### Generate a new tree

To generate a new vptree file, follow these steps:

Download and unzip the `abuse.ch` input from [here](https://bazaar.abuse.ch/export/csv/full/) as a CSV file named `download.csv` and save it in the same directory as the binary.
Run the binary using the following command: `./potash generate -c download.csv`
The vptree file will be created in the same directory as the binary (`./tree.gob` by default)

### search for a similar malware

Obtain the TLSH hash of the target malware by using VirusTotal (VT) or the tlsh binary.
Run the command `./potash runonce -s T1THEHASH`, where `T1THEHASH` is the TLSH hash of the target malware.
Wait for a few seconds until the tool loads up the vptree and then it will output the 10 nearest files and exit.
If you want to search for multiple hashes, you can run `./potash runinteractive`. 

## Contributions

Contributions to this project are welcome. Please open an issue or a pull request if you have any suggestions or improvements.

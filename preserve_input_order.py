import sys
from csv import DictReader
from argparse import ArgumentParser
from typing import Dict, List, Optional
from tracemac import fmac_cisco


def main():
    parser = ArgumentParser(
        description="Rewrite the output of a mac trace to the same order as the input data"
    )
    parser.add_argument(
        "ORIGINAL_INPUT", help="The original input file, 1 line per MAC"
    )
    operating_mode = parser.add_mutually_exclusive_group(required=True)
    operating_mode.add_argument(
        "--file", help="The output from MAC tracing in CSV format"
    )
    operating_mode.add_argument(
        "--stdin", help="Read the MAC trace from standard input", action="store_true"
    )
    args = parser.parse_args()
    trace_data = None
    if args.stdin:
        reader = DictReader(sys.stdin.readlines())
    else:
        with open(args.file, "r") as file_input:
            reader = DictReader(file_input.readlines())
    trace_data = [d for d in reader]
    with open(args.ORIGINAL_INPUT, "r") as original_input:
        print("mac,result,switch,interface")
        for line in original_input:
            line = line.strip()
            if mac := fmac_cisco(line):
                idx = locate(line, trace_data)
                if idx is not None:
                    found = trace_data[idx]
                    print(
                        "{},{},{},{}".format(
                            line, found["result"], found["switch"], found["interface"]
                        )
                    )
                else:
                    print(f"{line},failed,failed,failed")
                    print(f"Locate failed {line = } {trace_data = }", file=sys.stderr)
            else:
                print(f"{line},failed,failed,failed")
                print(
                    f"fmac_cisco failed: {line = } {fmac_cisco(line) = }",
                    file=sys.stderr,
                )


def locate(needle: str, haystack: List[Dict[str, str]]) -> Optional[int]:
    for idx, candidate in enumerate(haystack):
        if candidate["mac"] == needle:
            return idx
    return None


if __name__ == "__main__":
    main()

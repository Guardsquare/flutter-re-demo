import json
import argparse


from flure.parser.dwarf import DwarfParser
from flure.parser.reflutter import ReFlutterDumpParser


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Parse and reformat snapshot information")
    parser.add_argument("input", help="Input file to parse")
    parser.add_argument("input_type", choices=["dwarf", "reflutter"], help="Specify which parser should be used")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()
    if args.input_type == "dwarf":
        parser = DwarfParser(args.input)
    elif args.input_type == "reflutter":
        parser = ReFlutterDumpParser(args.input)
    else:
        raise Exception(f"Unknown input type {args.input_type}")

    if args.output is not None:
        with open(args.output, 'w') as fp:
            json.dump(parser.code_info.dump(), fp, indent=4)
    else:
        print(json.dumps(parser.code_info.dump(), indent=4))

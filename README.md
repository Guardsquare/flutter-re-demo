# flutter-re-demo

## Overview

This repository contains the files you need to reproduce our experiments on the feasibility of Flutter app reverse engineering.

You can find the non-obfuscated and obfuscated version of the [NyaNya Rocket!](https://github.com/CaramelDunes/nyanya_rocket) Flutter game that we used in our experiments.

You can use the [provided script](https://github.com/Guardsquare/flutter-re-demo/blob/main/parse_info.py) to format the output of [reFlutter](https://github.com/Impact-I/reFlutter) or DWARF file.
Later on, you can use the output of this script to rename/sort functions in IDA Pro using [this IDA Python script](https://github.com/Guardsquare/flutter-re-demo/blob/main/rename_flutter_functions.py).

## Disclaimer

These scripts are only provided for education purposes and are not meant to be stable reverse engineering tools.

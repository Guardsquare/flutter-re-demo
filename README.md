# flutter-re-demo

## Overview

This repository contains the files you need to reproduce our experiments on the feasibility of Flutter app reverse engineering. 

### Renaming of Dart functions

All details can be found in this [post](https://www.guardsquare.com/blog/current-state-and-future-of-reversing-flutter-apps).

You can find the non-obfuscated and obfuscated version of the [NyaNya Rocket!](https://github.com/CaramelDunes/nyanya_rocket) Flutter game that we used in our experiments.

You can use the [provided script](https://github.com/Guardsquare/flutter-re-demo/blob/main/parse_info.py) to format the output of [reFlutter](https://github.com/Impact-I/reFlutter) or DWARF file.
Later on, you can use the output of this script to rename/sort functions in IDA Pro using [this IDA Python script](https://github.com/Guardsquare/flutter-re-demo/blob/main/rename_flutter_functions.py).

### Dealing with Dart decompilation

All details can be found in this [post](https://www.guardsquare.com/blog/obstacles-in-dart-decompilation-and-the-impact-on-flutter-app-security).

The application used in the post is [the obfuscated APK](https://github.com/Guardsquare/flutter-re-demo/blob/main/samples/obfu.apk).

You can find the output of the Flutter memory dump [here](https://github.com/Guardsquare/flutter-re-demo/tree/main/samples/memory_dump). 
You can also generate it yourself using the [Frida script](https://github.com/Guardsquare/flutter-re-demo/blob/main/hooking/dump_flutter_memory.js).

You can import the memory dump into IDA Pro with [this script](https://github.com/Guardsquare/flutter-re-demo/blob/main/map_dart_vm_memory.py). 
Don't forget to rebase your database before running this script.

Once this is done, you can [create Dart object](https://github.com/Guardsquare/flutter-re-demo/blob/main/create_dart_objects.py) 
and [add cross-references](https://github.com/Guardsquare/flutter-re-demo/blob/main/add_xref_to_dart_objects.py) between Dart code and Dart objects.

If you want to see Dart object in decompiled code, you can register this [decompilation plugin](https://github.com/Guardsquare/flutter-re-demo/blob/main/add_dart_objects_in_decompiled_code.py).

You can also [patch Dart stack pointer register](https://github.com/Guardsquare/flutter-re-demo/blob/main/patch_dart_stack_pointer.py) to allow IDA Pro to identify function parameters and local variable.
Please note that it can generate incorrect code in function which are using both ``X15`` and ``SP``, thus use it only if you now what you are doing.

## Disclaimer

These scripts are only provided for education purposes and are not meant to be stable reverse engineering tools.

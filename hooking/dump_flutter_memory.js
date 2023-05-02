var FLUTTER_MEM_START = 0x7200000000
var FLUTTER_MEM_END = 0x7300000000
var FLUTTER_MEM_MASK = 0xff00000000
var SHARED_PREF_GET_INSTANCE_OFFSET = 0x6D4F88
var APP_DATA_DIR = "/data/data/fr.carameldunes.nyanyarocket/"

var flutter_map = {
    "object_pool": 0,
    "libapp_base": 0,
    "dump_ro": 0,
    "dump_rw": 0,
    "memory_dumps": []
};

var already_dumped = false;

function dump_memory(start_address, end_address, dump_directory) {
    let modules = Process.enumerateRanges("r--");
    let i, module, k;
    let module_file;
    let map_file;

    if (already_dumped) {
        return;
    }

    module_file = new File(dump_directory + "ranges.json", "wb");
    module_file.write(JSON.stringify(modules, null, 2));
    module_file.close();

    k = 0
    for (i = 0; i < modules.length; i++) {
        try {
            module = modules[i];
            if ((module.base.compare(start_address) >= 0) && (module.base.compare(end_address) <= 0)) {
                console.log(`Dumping ${i} memory into ${dump_directory + module.base}`);
                module_file = new File(dump_directory + module.base, "wb");
                module_file.write(module.base.readByteArray(module.size));
                module_file.close();

                if (k == 0) {
                    flutter_map["dump_ro"] = module.base;
                    k++;
                } else if (k == 1) {
                    flutter_map["dump_rw"] = module.base;
                }
                flutter_map["memory_dumps"].push(module.base)
            }
        } catch(ex) {
            console.log(ex);
            console.log(JSON.stringify(module, null, 2));
        }
    }

    map_file = new File(dump_directory + "dump_info.json", "wt");
    map_file.write(JSON.stringify(flutter_map, null, 2));
    map_file.close();

    already_dumped = true;
}

function hook_libapp() {
    var base_address = Module.findBaseAddress("libapp.so");
    console.log(`Hooking libapp: ${base_address} `);
    flutter_map["libapp_base"] = `${base_address}`;

    Interceptor.attach(base_address.add(SHARED_PREF_GET_INSTANCE_OFFSET), {
        onEnter: function (args) {
            if (already_dumped) {
                return;
            }
            console.log(`SharedPreferences::getInstance() `);
            console.log(` X27: ${this.context.x27}`)
            flutter_map["object_pool"] = `${this.context.x27}`
            if (this.context.x27.and(FLUTTER_MEM_MASK) == FLUTTER_MEM_START){
                dump_memory(FLUTTER_MEM_START, FLUTTER_MEM_END, APP_DATA_DIR)
            }else{
                console.error(`Default flutter memory ${ptr(FLUTTER_MEM_START)} seems incoherent with X27 ${this.context.x27}`)
                console.error(`Please modify FLUTTER_MEM_START, FLUTTER_MEM_END`)
            }
        }
    });
}


var already_hooked = false;
function hook_dlopen(target_lib_name, lib_hook_callbacks) {
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function (args) {
            let lib_name = args[0].readCString();
            this.do_hook = false;
            if (lib_name == target_lib_name) {
                if (!already_hooked) {
                    this.do_hook = true;
                    already_hooked = true;
                }
            }
        },
        onLeave: function (retval) {
            if (this.do_hook) {
                lib_hook_callbacks()
            }
        }
    });
}
hook_dlopen("libapp.so", hook_libapp)
// frida -U -f fr.carameldunes.nyanyarocket -l dump_flutter_memory.js --no-pause

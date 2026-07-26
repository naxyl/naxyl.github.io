/// <reference types="frida-gum" />
import { log } from "./logger.js";
import Java from "frida-java-bridge";

/*
  ###### 1. HOOKING STRSTR TO BYPASS NATIVE PROTECTIONS
*/
// Let's retrieve the libc library
const libc = Process.findModuleByName("libc.so");

// This is unlikely to happen, but we have to do this check for the file to compile
if (!libc) {
    throw new Error("Could not find libc.so");
}

// From the libc, we find the strstr function we want to hook
const strstr = libc.findExportByName("strstr");

// Same here, unlikely to happen but for the compilation
if (strstr === null) {
    throw new Error("Failed to find strstr inside libc.so");
}

// Then we can use the interceptor to attach to the function we want to hook
Interceptor.attach(strstr, {
    onEnter: function (args) {
        // We save the second argument for later (onLeave)
        this.needle = args[1].readCString();
    },
    onLeave: function (retval) {
        // If the searched string (needle) is frida or xposed, we return a null pointer (behaving like the substring has not been found)
        // I added the xposed for genericity but we're not actually concerned by this
        if (this.needle.includes("frida") || this.needle.includes("xposed")) {
            // log("Hiding: " + this.needle);
            retval.replace(ptr(0));
        }
    }
});

/*
   ###### 2. HOOKING TO BYPASS JAVA PROTECTIONS
*/
Java.perform(() => {
    // This is to hook the exit handler function named "showDialog"
    const MainActivity = Java.use('sg.vantagepoint.uncrackable3.MainActivity');
    // Overload is mandatory because of the asynchronous task in onCreate(...) explained in UncrackableL2 already
    MainActivity.showDialog.overload('java.lang.String').implementation = function (param1: string) {
        log("Pop up successfully blocked");
    }
});

/*
  ###### 3. FINDING THE ENCRYPTED FLAG 
*/

/*
   The function that is going to find the libfoo.so, find the 
   generate_encrypted_flag address. 
   Then hook it by displaying args[0] after it's been filled with
   the encrypted values
*/
/*
   The function that is going to find the libfoo.so, find the 
   generate_encrypted_flag address. 
   Then hook it by displaying args[0] after it's been filled with
   the encrypted values
*/
function hookGenerateEncryptedFlag() {
    // We retrieve the lib, so we get the base address
    const libfoo = Process.findModuleByName("libfoo.so");

    if (!libfoo) {
        throw new Error("Could not find libfoo.so");
    }

    // Then we get the base address of libfoo
    const base_address = libfoo.base;
    // The offset retrieved on Ghidra
    const ghidra_gef_offset = 0xfa0;

    // By adding the base address + the func offset, we retrieve the func object
    const generate_encrypted_flag_func = base_address.add(ghidra_gef_offset);

    // And we hook it, we just want to see the args[0] value as it changed during the function execution
    Interceptor.attach(generate_encrypted_flag_func, {
        onEnter: function (args) {
            // We retrieve the pointer to the encrypted_flag array
            this.encrypted_flag = args[0];
        },
        onLeave: function () {
            // args[0] has been filled, so we now dump its value
            let encrypted_flag_bytes = this.encrypted_flag.readByteArray(25);

            // Now, let's reconstruct the flag directly here
            const xorkey = "pizzapizzapizzapizzapizz";

            // We convert the encrypted flag bytes as an Iterable Array
            const iterable_array = new Uint8Array(encrypted_flag_bytes);

            let flag = "";
            for(let i = 0; i < 25; i++){
                // We do the xor operation between the encrypted flag element
                //  and the xorkey element at the i index
                const decrypted_byte = xorkey.charCodeAt(i) ^ iterable_array[i];

                // and then we convert the raw byte to a char and append it to the flag string
                flag += String.fromCharCode(decrypted_byte);

            }

            log("Flag : " + flag);

        }
    });
}


/* Here we hook the dlopen native function so we can know
the exact moment when libfoo.so is loaded, and consequently when to
hook one of its function
*/
// We retrieve the library
const libdl = Process.findModuleByName("libdl.so");
// Usual check
if (!libdl) {
    throw new Error("Could not find libdl.so");
}
// Then we retrive the dlopen function
const dlopen = libdl.findExportByName("android_dlopen_ext") 
// Usual check
if (dlopen === null) {
    throw new Error("Failed to find dlopen inside libdl.so");
}

// And we hook it ! 
Interceptor.attach(dlopen, {
    onEnter: function (args) {
        // Incase there would be calls from other 
        // processes that could break the interceptor
        if (!args[0].isNull()) {
            (this as any).libName = args[0].readCString();
        } else {
            (this as any).libName = null;
        }
    },
    onLeave: function (retval) {
        // We let every library loads in order not to break anything
        const libName = (this as any).libName;
        
        // If it's libfoo.so, we trigger and execute our generate_encrypted_flag hook function
        if (libName && libName.includes("libfoo.so")) {
            log("dlopen intercepted libfoo.so!");
            hookGenerateEncryptedFlag();
        }
    }
});
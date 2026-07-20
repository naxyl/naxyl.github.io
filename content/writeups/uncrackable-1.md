---
date: '2026-07-20T10:35:08+02:00'
draft: false
title: 'OWASP MASTG - Android'
---
# Android Uncrackable L1

<u>Statement</u> : A secret string is hidden somewhere in this app. Find a way to extract it.

## Resources
Here are the resources I found during the reverse engineering and exploitation processes. 
- https://medium.com/@ahmedafatah/android-security-for-dummies-root-detection-695bd4d90db8



## First analysis
We get [this APK file](UnCrackable-Level1.apk) : 
```sh
> file UnCrackable-Level1.apk 
UnCrackable-Level1.apk: Android package (APK), with AndroidManifest.xml, with APK Signing Block
```

So there's obviously the **AndroidManifest.xml** file containing the app metadata. The `file` command also shows the presence of the **APK Signing Block**. 

> An **APK Signing Block** is a dedicated section within an APK. It stores the **app's cryptographic signatures and developer identity**, ensuring the app is authentic, hasn't been tampered with, and safely installs on the Android operating system.

We can install the APK file on our **emulated rooted device** : 
```sh
adb install UnCrackable-Level1.apk 
Performing Streamed Install
Success
```

While launching the app, we see it detects right away the device is rooted. 

![alt text](/img/detected.png)  



## Static reverse with JADX

Let's inspect the source code in order to understand **how the root detection is made** so we'll be able to understand how to bypass it. 

By looking at the `onCreate` function (*the start of the app lifecycle*) we can see that **four verifications** are made before letting the user access the app. 

![alt text](/img/oncreate.png)

Now, we can look for the "`c`" class to see the **Anti-Root** protections. Here is the commented version :
```java
public class c {
    // Searches in the PATH env variable for
    // the "su" binary (meaning the device is rooted)
    public static boolean a() {
        for (String str : System.getenv("PATH").split(":")) {
            // checks if str/su file exists
            // if it does, returns true
            if (new File(str, "su").exists()) {
                return true;
            }
        }
        return false;
    }

    public static boolean b() {
        String str = Build.TAGS;
        return str != null && str.contains("test-keys");
    }

    public static boolean c() {
        for (String str : new String[]{"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon", "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/"}) {
            if (new File(str).exists()) {
                return true;
            }
        }
        return false;
    }
}
```

### 1. `c.a()` :  Protection via PATH
To bypass this, let's first look at our PATH on our Android device : 
```sh
> adb shell 'echo $PATH'
/sbin:/system/sbin:/product/bin:/apex/com.android.runtime/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin
```
After running this command, we can see which directories of our device path contains the `su` binary : 
```sh
> adb shell 'for d in $(echo $PATH | tr ":" " "); do ls $d 2>/dev/null | grep "^su$" >/dev/null && echo $d; done'

/system/bin
/system/xbin
```

> Here, there are two ways of bypassing this. 
> 1. The easiest way : **Change the return value of this function** with Frida scripting, so it returns `false` no matter what.
> 2. The hardest way : Install LSPosed Framework, Magisk. Then, flash the Shamiko module with Magisk...so the `/system/bin/su` and `/system/xbin/su` are hidden. It's heavy but works against real production apps. Here's a link to follow the process : https://droidwin.com/how-to-hide-su-file-and-magisk-file/


We'll go with the first way as the second one would require to setup the Android device with multiple apps/frameworks and this is overkill for such a crackme. 

### 2. `c.b()` : Protection via Build Tags
```java
public static boolean b() {
    String str = Build.TAGS;
    return str != null && str.contains("test-keys");
}
```
We can see the verification made on `Build.TAGS`

The [documentation]() says the `android.os.Build.TAGS` is a **string** containing comma-separated tags describing the build, like "*unsigned*,*debug*". 

There's a post on Stackoverflow asking what is this root detection doing : 
- https://stackoverflow.com/questions/18808705/android-root-detection-using-build-tags

As for `c.a()`, we'll just **override this method** for it to **return false**.

### 3. `c.c()` : Protection via existing files checking
This method checks if those files exist. If **at least one of them** does, it returns true. 
```java
public static boolean c() {
    for (String str : new String[]{"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon", "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/"}) {
        if (new File(str).exists()) {
            return true;
        }
    }
    return false;
}
```

For a third time, we'll use Frida's ability to hook methods so it returns false. 

### 4. `b.a()` : Anti-debug protection via
We now can look for the "`b`" class as we know how to bypass the 3 anti-root protections seen before. 

```java
public class b {
    public static boolean a(Context context) {
        return (context.getApplicationContext().getApplicationInfo().flags & 2) != 0;
    }
}
```
What this method does is reading the 2nd least significant bit and : 
1. Returns *true* if the flag is set. 
2. Returns *false* if the flag is not set.

After reading the [Android documentation](https://developer.android.com/reference/android/content/pm/ApplicationInfo#flags
), we can see the flag located at the 2nd least significant bit is the `FLAG_DEBUGGABLE` constant. 

If the bit is set, it means that the application would like to allow debugging of its code. It's not set by default as we didn't modify the app source code, so it's not allowing debugging. 

Once again, we'll hook this function with Frida so it returns false no matter what. 

## Function hooking with Frida JS API
We can use TypeScript to write our JS script so we'll get the autocompletion. 

### Setup

#### Scripting requirements

In order to be able to write in TS, we have to setup like this : 
```sh
git clone https://github.com/oleavr/frida-agent-example.git /tmp/temp_frida

cp -r /tmp/temp_frida/. .

rm -rf temp_frida .git
```

We know have to write our script in [agent/index.ts](agent/index.ts). 

> We also have to run `npm run watch` in a terminal so the typescript will automatically will be translated to javascript in real time. 
> 
> In addition, append this at the top of the `index.ts` file so it recognises Java etc. and the autocompletion works. 
> `/// <reference types="frida-gum" />`

#### Frida server
As our android device is rooted, we can simply install the [frida-server](https://github.com/frida/frida/releases/download/17.16.0/frida-server-17.16.0-android-x86.xz) on the device. 

Once again, we just have to follow what the documentation says : 
- https://frida.re/docs/android/

So it should look like that : 
```sh
$ adb root
adbd is already running as root
$ ls
- frida-server-17.16.0-android-x86
$ mv frida-server-17.16.0-android-x86 frida-server
$ adb push frida-server /data/local/tmp/
frida-server: 1 file pushed, 0 ...MB/s (53935444 bytes in 0.164s)
$ adb shell "chmod 755 /data/local/tmp/frida-server"
$ adb shell "/data/local/tmp/frida-server &"
```
### Scripting the hooking

Now the server is running, let's write our script. 

The documentation is easy to understand, so to hook a function we do : 
```java
const classWeWant = Java.use('package.classname');
classWeWant.methodName.implementation = function () {
    // whatever we want here
}
```

Let's see if the message changes with this script, as it hooks the 3 anti root protection functions : 
```ts
/// <reference types="frida-gum" />

import Java from "frida-java-bridge";
import { log } from "./logger.js";

Java.perform(() => {
    const cClass = Java.use('sg.vantagepoint.a.c');
    cClass.a.implementation = function () {
        return false;
    }
    cClass.b.implementation = function () {
        return false;
    }
    cClass.c.implementation = function () {
        return false;
    }
})
```

We can use this command 
```sh
$ frida -U -f owasp.mstg.uncrackable1 -l _agent.js
     ____
    / _  |   Frida 17.16.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   Prefer a GUI? Luma is the official Frida app, with a live REPL,
   . . . .   persistent sessions & collaboration. https://luma.frida.re/
   . . . .
   . . . .   Connected to Pixel 3 (id=127.0.0.1:6555)
Spawned `owasp.mstg.uncrackable1`. Resuming main thread!                
[Pixel 3::owasp.mstg.uncrackable1 ]->
```

Looking at our device, we can see **the anti root warning disappeared** and that we can nowenter the string we want in the input field. 

![alt text](/img/bypassed.png)

## Finding the secret
Now that we can do whatever we want on the app as we bypassed the anti-root and anti-debug protections, let's find the string to validate this crackme. 

This function is called whenever the user clicks on the "Verify" button. 
```java
public void verify(View view) {
    String str;
    String string = ((EditText) findViewById(R.id.edit_text)).getText().toString();
    AlertDialog alertDialogCreate = new AlertDialog.Builder(this).create();
    if (a.a(string)) {
        alertDialogCreate.setTitle("Success!");
        str = "This is the correct secret.";
    } else {
        alertDialogCreate.setTitle("Nope...");
        str = "That's not it. Try again.";
    }
    alertDialogCreate.setMessage(str);
    alertDialogCreate.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable1.MainActivity.2
        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialogInterface, int i) {
            dialogInterface.dismiss();
        }
    });
    alertDialogCreate.show();
}
```

This is the interisting part. It takes the user input - the "`string`" variable - 
```java
if (a.a(string)) {
    alertDialogCreate.setTitle("Success!");
    str = "This is the correct secret.";
}
```

Going into the "`a`" class of the `sg.vantagepoint.uncrackable1` package, we find this "`a`" method : 
```java
public static boolean a(String str) {
    byte[] bArrA;
    byte[] bArr = new byte[0];
    try {
        bArrA = sg.vantagepoint.a.a.a(b("8d127684cbc37c17616d806cf50473cc"), Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));
    } catch (Exception e) {
        Log.d("CodeCheck", "AES error:" + e.getMessage());
        bArrA = bArr;
    }
    return str.equals(new String(bArrA));
}
```
Instead of wasting time trying to understand the crypto operations, let's hook the `sg.vantagepoint.a.a.a` function so it directly prints the value it computes (the expected value for our input).

We can append this at the end of our [index.ts](agent/index.ts) : 
```ts
const aClass = Java.use('sg.vantagepoint.a.a');
aClass.a.implementation = function(arg1: any, arg2: any) {
    // By writing this.a() aka the method we're currently hooking
    // we can execute the original code before the one we define gets executed
    const secret = this.a(arg1, arg2);

    // so we get a byte array 
    // let's convert it to a string
    var result = "";
    log("Secret size : " + secret.length);
    log("Secret raw : " + secret);
    for (var i = 0; i < secret.length; i++) {
        result += String.fromCharCode(parseInt(secret[i], 10));
    }

    log("Secret (array bytes -> string) : " + result);

    return secret;
}
```

By relaunching the script injection and submitting a random input, we indeed get the computed secret !

![alt text](/img/flag.png)  

```
I want to believe
```⏎     
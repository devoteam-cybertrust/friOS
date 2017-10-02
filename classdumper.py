"""
Frida script to dump the classes specific to the app binary

# (c) 2017 INTEGRITY S.A.
# By: Herman Duarte <hd@integrity.pt>

"""

import frida
from time import sleep
import sys

script_test = '''
'use strict';

rpc.exports = {
    classes: function () {
        if (ObjC.available) { return ObjC.classes; }
    },
    getClassOwnMethods: function (className) {
        return ObjC.classes[className].$ownMethods;
    }
};
'''

#appToLaunch = 'com.example.ios.app'
appToLaunch = None

if appToLaunch == None:
    if len(sys.argv) > 1:
        appToLaunch = sys.argv[1]
        print(appToLaunch)
    else:
        print("usage: python3 " + sys.argv[0] + " <app identifier>")
        print("       python3 " + sys.argv[0] + " com.example.ios.app")
        sys.exit (0)

device = session = pid = None

try:
    device = frida.get_usb_device()
    pid = device.spawn([appToLaunch])
    sleep(1)
    
    session = device.attach(pid)
    device.resume(pid)

    # selecting only the app binary to inspect
    appModule = session.enumerate_modules().pop(0)
    appModuleRanges = appModule.enumerate_ranges('---')

    script = session.create_script(script_test)
    script.load()
    ObjC = script.exports

    # getting all classes that are loaded
    classes = ObjC.classes()
    own_classes = {}
    count = 0

    print('[*] All classes of module: ' + appModule.name)
    for classname in classes:
        classptr = classes[classname]['handle']

        for range in appModuleRanges:
            classptr_int = int(classptr, 16)

            if classptr_int >= range.base_address and classptr_int <= (range.base_address + range.size):
                print('  [*] ' + classname)
                methods = ObjC.get_class_own_methods(classname)
                for method in methods:
                    print('    [*] ' + method)

                count += 1

    sleep(1)
    print('Total classes found: ' + str(len(classes)))
    print(appModule.name + ' specific classes found: ' + str(count))

    script.unload()
    device.kill(pid)

except:
    print("Device is not connected, check your USB connection")
    raise


"""
    ToDo:
     - find the params types and print the methods full signature
     - 
"""
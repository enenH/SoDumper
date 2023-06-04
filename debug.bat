adb forward tcp:12345 tcp:1234
adb push outputs\arm64-v8a\%1 /data/local/tmp
adb shell su -c chmod +x /data/local/tmp/%1
adb shell su -c /data/local/tmp/gdbserver 0.0.0.0:1234 /data/local/tmp/%1
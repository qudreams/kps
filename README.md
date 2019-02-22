## kps

### Note
> kps is a simple kernel module to get running task cmd-line arguments in kernel like \`ps\` command.

### Usage
1. compile
> make
2. add kernel-module kps.ko:
> /sbin/insmod kps.ko
3. show result
> dmesg
4. remove kernel-module
> /sbin/rmmod kps.ko

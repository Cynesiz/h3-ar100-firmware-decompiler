#!/bin/sh

./bin/or1k-elf-objcopy -I binary -O binary -B or1k --reverse-bytes=4 arisc_sun8iw7p1.bin arisc_sun8iw7p1.rev.bin
xxd arisc_sun8iw7p1.rev.bin > arisc_sun8iw7p1.hex.txt

./bin/or1k-elf-objcopy -I binary -O elf32-or1k -B or1k --reverse-bytes=4 arisc_sun8iw7p1.bin arisc_sun8iw7p1.elf
./bin/or1k-elf-objdump -D arisc_sun8iw7p1.elf > arisc_sun8iw7p1.as

php decompile.php arisc_sun8iw7p1.as arisc_sun8iw7p1.rev.bin > arisc_sun8iw7p1.c

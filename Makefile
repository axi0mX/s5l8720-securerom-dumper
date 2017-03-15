all:
	arm-elf-eabi-as -march=armv6 -mthumb --fatal-warnings -o build/shellcode.o shellcode.S
	arm-elf-eabi-objcopy -O binary build/shellcode.o build/shellcode.bin
	rm build/shellcode.o


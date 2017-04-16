all:
	arm-none-eabi-as -march=armv6 -mthumb --fatal-warnings -o bin/shellcode.o src/shellcode.S
	arm-none-eabi-objcopy -O binary bin/shellcode.o bin/shellcode.bin
	rm bin/shellcode.o

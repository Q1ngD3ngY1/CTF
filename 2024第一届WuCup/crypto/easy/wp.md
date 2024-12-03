# easy题解
## 分析与解答
拿到文件后，直接丢给AI写一个s[i]的生成脚本，并解密，即可拿到flag：
```python
def modified_rc4(key, encrypted_msg):
    key_len = len(key)
    permutation = list(range(256))
    key_schedule = [ord(char) for char in key * (256 // key_len + 1)]
    index_j = 0

    # 初始化置换表
    for i in range(256):
        index_j = (index_j + permutation[i] + key_schedule[i]) % 256
        permutation[i], permutation[index_j] = permutation[index_j], permutation[i]

    index_i = 0
    index_j = 0
    decrypted_msg = []

    # 解密消息
    for byte in encrypted_msg:
        index_i = (index_i + 1) % 256
        index_j = (index_j + permutation[index_i]) % 256
        permutation[index_i], permutation[index_j] = permutation[index_j], permutation[index_i]
        permutation_index = (permutation[index_i] + permutation[index_j]) % 256
        decrypted_byte = byte ^ permutation[permutation_index]
        decrypted_msg.append(decrypted_byte)

    return ''.join(chr(byte) for byte in decrypted_msg)

# 密钥和密文
key = "hello world"
encrypted_msg = [0xd8, 0xd2, 0x96, 0x3e, 0x0d, 0x8a, 0xb8, 0x53, 0x3d, 0x2a, 0x7f, 0xe2, 0x96, 0xc5, 0x29, 0x23, 0x39, 0x24, 0x6e, 0xba, 0x0d, 0x29, 0x2d, 0x57, 0x52, 0x57, 0x83, 0x59, 0x32, 0x2c, 0x3a, 0x77, 0x89, 0x2d, 0xfa, 0x72, 0x61, 0xb8, 0x4f]

# 解密
decrypted_msg = modified_rc4(key, encrypted_msg)
print(f"解密后的消息: {decrypted_msg}")
```

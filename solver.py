def decrypt(A:int, B:int, key:int)->int:
    result = ((key << 5) ^ ((key << 2) | (B >> 4)) ^ B) & 0xFF
    result = result ^ A
    return result

def decrypt_pair(a: int, b: int, key: list[int]):
    for k in key:
        result = decrypt(a, b, k)
        a = b
        b = result
    return (a, b)

counter=0
encrypted_flag = [0x16, 0x46, 0x02, 0x51, 0x08, 0x5e, 0x4f, 0x11, 0x3f, 0x78, 0x41, 0x51, 0x4a, 0x4e, 0x05, 0x15, 0x51, 0x12, 0x2e, 0x78, 0x2c, 0x5c, 0x7c, 0x10, 0x4a, 0x12, 0x5d, 0x01, 0x41, 0x15, 0x6d, 0x22]

for k1 in range(0,255):
    for k2 in range(0,255):
        for k3 in range(0,255):
                result = decrypt_pair(0x16,0x46,[k1,k2,k3])[1]
                if result == 98:#second character is b
                    for k4 in range(0,255):
                        result = decrypt_pair(0x16,0x46,[k1,k2,k3,k4])[1]
                        if result == 97:#first character is a
                            b, result = decrypt_pair(0x02,0x51,[k1,k2,k3,k4])
                            if result == 99 and b == 116:#third character is c and fourth character is t
                                b, result = decrypt_pair(0x08,0x5e,[k1,k2,k3,k4])
                                if result == 102 and b == 123:#fifth character is f and sixth character is {
                                    result= decrypt_pair(0x6d,0x22,[k1,k2,k3,k4])[1]
                                    if result == 125:
                                        decrypted_flag = []
                                        key = [k1,k2,k3,k4]

                                        for i in range(0, len(encrypted_flag), 2):
                                            a = encrypted_flag[i]
                                            b = encrypted_flag[i+1]

                                            for k in key:
                                                result = decrypt(a, b, k)
                                                a = b
                                                b = result

                                            decrypted_flag.append(chr(b))
                                            decrypted_flag.append(chr(a))
                                        print(key)
                                        print("".join(decrypted_flag))

print(counter)


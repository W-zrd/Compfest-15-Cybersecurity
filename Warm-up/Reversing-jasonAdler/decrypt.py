def modified_decrypt(enc_text):
    holder1 = [ord(x) for x in enc_text]
    text = [0] * len(enc_text)
    
    # menghitung text dari holder1
    text[0] = holder1[0] - 1
    for i in range(1, len(enc_text)):
        text[i] = (holder1[i] - holder1[i-1]) % (2**9 << 16)
        
    # mengubah setiap nilai dalam text menjadi karakter, mengabaikan nilai-nilai yang tidak valid
    text = [chr(x) for x in text if 0 <= x < 0x110000]
    
    return ''.join(text)

# mendekripsi setengah pertama dari enc_text
enc_txt = open("enc.txt","r").read()
decrypted_text = modified_decrypt(enc_txt)
print(decrypted_text)

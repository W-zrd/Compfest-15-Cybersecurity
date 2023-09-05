
Here is a list of problems my team completed, you can download it in the PDF file above. Actually there are still **some challenges that have not been resolved** in the qualifying round. And **those are included in this `README.md` but excluded in PDF File**. And also, the COMPFEST CTF platform is currently down so i can't make Proof of Concept on some challenges.


# 1. Industrial Spy
*Author: k3ng*

Dear IT guy, I have suspicions that our graphic designer intern is stealing confidential documents and sending them to our competitor. I have sent her PC's memory dump to analyze.

Attachment: https://drive.google.com/file/d/18u8OSCejwV5Wo7Ezh7NLlVpuhkMQbw4d/view?usp=sharing

Hint 1: 8335370

## Solution
Diberikan sebuah memory dump berformat *.mem* . Lakukan analisis dengan Volatility (saya menggunakan versi 2). Namun sebelum menganalisis lebih lanjut, kita perlu tahu base profile yang digunakan pada memory dump ini agar bisa make plugin volatility lainnya.
```
volatility -f lyubov_20230712.mem imageinfo
```
Biasanya hasil yang muncul paling depan adalah yang paling match dengan memory dumpnya.

![imageinfo](img/imageinfo.png)

Setelah tau base profilenya, kita bisa menggunakan plugin volatility. Untuk menampilkan daftar proses yang sedang berjalan dalam snapshot memori, gunakan plugin `pslist`

```
volatility -f lyubov_20230712.mem --profile=Win7SP1x64 pslist
```
![pslist](img/pslist.png)

Proses yang berjalan tidak banyak sehingga tidak terlalu sulit untuk menganalisisnya. Berdasarkan deskripsi soal, orang yang mencurigakan bekerja sebagai desainer. Jadi saya mencari software yg berkaitan dengan desain pada process list di atas, dan ketemu `mspaint.exe` dengan PID 1320. Extract PID tersebut.

```
volatility -f lyubov_20230712.mem --profile=Win7SP1x64 memdump -p 1320 -D .
```

Setelah di extract, maka akan muncul file baru bernama `1320.dmp`. Ubah format file tsb menjadi `1320.data` agar bisa terbaca oleh GIMP. Disini kita perlu mengotak-atik value dari width, sedangkan untuk height bisa pakai 800 pixel saja sebagai permulaan.

Berdasarkan hint pada soal, terdapat nilai `8335370` yang ketika pertama kali saya lihat, saya tidak paham maksud hintnya. Namun nilai itu sebenarnya adalah offset gambarnya. Jadi intinya yang perlu kita cari tau adalah width imagenya. Berikut adalah settingan gambar hingga muncul flag.

```
Offset: 8335368
Width : 1020
Height: 800
```

![rotatedflag](img/rotatedflag.jpg)

# 2. Not Simply Corrupted
*Author: notnot*

My friend loves to send me memes that has cats in it! One day, he sent me another cat meme from his 4-bit computer, this time with “a secret”, he said. Unfortunately, he didn’t know sending the meme from his 4-bit computer sorta altered the image. Can you help me repair the image and find the secret?

## Solution
![corrupted](img/corrupted.png)

File attachment yang diberikan soal berformat .PNG. Dan jika dibuka, Gambar tersebut akan *corrupt* atau tidak terbaca oleh image viewer. Untuk itu, lihat isi hex dari file tsb dengan hex editor.

![xxd](img/xxd.png)

Terlihat bahwa header dan struktur dari PNG ini rusak, bahkan isinya hanya angka biner `0` dan `1`.  Setiap file PNG biasanya diawali oleh hex `89 50 4E 47 0D 0A 1A 0A` dan diakhiri oleh `00 00 00 00 49 45 4E 44 AE 42 60 82`. Karena isi dari file ini seluruhnya hanya angka `0` dan `1`, dan juga sesuai deskripsi pada soal, mungkin saja nilai biner ini merupakan hasil encoding dari hex.

Decode seluruh bilangan biner tersebut menjadi hex lalu simpan sebagai PNG. Hal ini bisa dilakukan dengan scripting python atau bisa juga dengan [tools online berikut](https://cryptii.com/pipes/binary-decoder) dan [Hexedit](https://hexed.it/). Maka akan didapat gambar kucing :

![cat](img/cat.png)

Tidak ada flag dalam gambar tersebut. Namun bisa jadi flagnya disembunyikan pada gambar tsbb dengan teknik steganography. Untuk memastikannya, saya menggunakan [tools online ini](https://www.aperisolve.com/), lalu didapat flag.

![steg](img/steg.png)

# 3. E2EBleed
*Author: rorre*

Someone in my house seems to be doing something fishy again… Maybe this time I will investigate. I’ve tapped into the connection of said person’s internet, perhaps you could help me find what they’re doing?

The (compiled) code and docker files required to run the set up locally are provided.

To deploy locally, simply run `docker compose up --build -d`. You can go to `http://localhost:444/` to access the site.

***NOTE***: Use `chall-olddocker.zip` if you use docker 20, if you have newer version, chall.zip should work just fine.

***Hint 1:*** Browser's devtools is an amazing tool. Maybe look at the source and network tab to figure things out?
***Hint 2:*** Try looking at the lifecycle of the chat, it's also using a common cryptography technique in CTF challenges.


## Solution
**Solved by: PwnEater**

Diberikan sebuah file pcap dan source code dari aplikasi (frontend dan backend). Pertama analisis terlebih dahulu file pcap, dan ditemukan app untuk berkomunikasi yang menggunakan websocket :

![](https://lh6.googleusercontent.com/lODUvJzY0gt03qQlWW4c_96dGSeFF_TO9JlSM1UvvnHpsGWbuMTje6qx8MuMN6xf5jcyjV3qg80KpvOMoiwxzqcToyI3OClDT-545cxgELocmxvJfP4Ok6r89jq8A-TowDzilR1XBa2VW32cGpl1Huc)

Terdapat 2 type data yang dikirimkan, pertama `v` dan `message`, kita cari tau bagaimana app menggunakan `message` dan `v` tersebut. ditemukan potongan source code sebagai berikut pada frontend yang telah dibuild :

![](https://lh4.googleusercontent.com/c7kvWRLZoC6ruzDfFCdJNhTzEAJtOBhwvttnFk5nKE6WZeyUSSF2tJO0gX__4LsVeJ6wo6iU1S9tWUUEbHovBhJNtVJUCnHvalhWiXdSAxKJkmALBGPsyGZa30q7UVBf_mcQhR6Vd1YH6xnRgD0dp8k)

  

Terlihat bahwa test yang akan ditampilkan di halaman chat akan proses pada fungsi `qp()` dengan parameter nilai Big Integer dari message terenskripsi, variable o yang berisi nilai eksponen `0x10001` dan nilai modulus n. Perumusan  Ke 3 parameter tersebut awalnya diperoleh dari potongan kode berikut :

![](https://lh3.googleusercontent.com/t_g-ztwYQb50nekptiSYbP4YBMY49fTwHwjP2YWJQff8ZpvYsETbj3dgYJTBP7tgNXp1_j4uQRtqsqvp_rMrPKGfXcMPwfaYPUB8DkwRsDGoFkuwarEMiGhBwCZWkMIPUZO2lWYuti2TEDwyQII5MeI)

  

Terdapat 2 kondisi, namun kita akan berfokus pada kondisi else untuk teks teks yang lebih panjang terlebih dulu. Implementasi ulang mekanisme tersebut dan copy juga seluruh fungsi yang berkaitan dengan prosesnya maka diperoleh kode sebagai berikut :

  
  
![](https://lh5.googleusercontent.com/aBbzqHs7O3DelOsDZXxyijKF53DXvQ0ogXoxgF_F3sXES8C36TiMQQZGHtg7w10AbBQnku5EyvJ_0Dte7cRjCPDU30oNziA1wrZTpCajGl9iKoVA7cmoqpvnMEpHp1lFJuU1AF27RvDZyRaNCwPa06w)

  

Run kode tersebut, namun dari pesan2 tersebut, tidak diperoleh flag :\

![](https://lh6.googleusercontent.com/Wzf4bTbdFZ18hzEM4GTv7_33xdUnWTU8BMRgGosnDa17r8Esa_2jAaXjYj_I38oKFzA7yFjKLTdc2fK6lqNqhYXcieur97iS4WO9EPf6xn1svsfcG1z9tYnEF3seBC39-cHZGt0zao9M6AnM8PI_gTM)
  
Ternyata **terdapat beberapa bagian paket yang di MASK**, berikut contohnya :  
![](https://lh3.googleusercontent.com/RS00NawfKYcasUaaJ_HwaEb0zLfNefCvmizvPWy30jOKQ_M1NOqDjxhfS5Xn3GsiKjB8qn6ArV_U67gHMR1dnV2zyLgziPFuUYpuHFaKqXUxNb5Pn9O-u09wnzp91kUolowFixYAAhK7xZ9cC4VCnlg)

Untuk mendapatkan key untuk xor data yg di mask sangat mudah, xor saja dengan key yang terdapat di paket data tersebut :

![](https://lh4.googleusercontent.com/NtEWTKwERKeOca_SqhPWcsInGombySN2UEwRsf0kxT7fOzkMlSotVo_xtz5WneTHZg_67OtGZfGHY_jlbxPHNyRy9_i5PXJL1js8NwA4fNdguL7ZyaWMSleKxJ7iRS6WNr3BGxGrBaNxWiPK3NInhss
  
Gunakan script berikut untuk unmasking :

![](https://lh6.googleusercontent.com/mMaZ7Js-pUxN5v9UjFwgu2vnerjD9cgC5cgPYZQSFK2iq0LTHNxRBvfa0i3xpDZfD_6WDq2jGP1EVwmcHbodOwsrdid3jE_42m-BJ9fWvd6UCdSpBdNs-bRD_vs7dkTzLwUCY5CK5Rw58FeToBMCh3Y)
Run script tersebut dan diperoleh plain text nya :

![](https://lh5.googleusercontent.com/YmeU2KrS_KnDpcNHYVH2iOHrPvhxliDbSxHNAbfJa39RxYvfG3haq4e1gS3te2-3d1Np59n4kDdAR08ELZH8aSuzqccxSHybS6WtCUGattmg8D6LY41yj3xSdUBFDbJlLug7GqnpLNhgbWX5ThvUOQM)

Masukan cipher cipher tersebut ke solver script awal tadi maka diperoleh flag sebagai berikut :

![](https://lh6.googleusercontent.com/Dev4EB4uv5GFm7VWikrvuYBfgs9rb7xy6jo6hOgJXfg0LFsepHRTozUrANTSpdIfKpq1TEA92ofUh3p5lfHonVDm5mHODyKpfIlicmo2GR_a8cgGomVraQN2jd9Gq4_5x7JOh7pStr7ziKOD5ZTRueI)



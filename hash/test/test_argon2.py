


"""

6.  Test Vectors

   This section contains test vectors for Argon2.

6.1.  Argon2d Test Vectors

   =======================================Argon2d
   Memory: 16 KiB
   Iterations: 3
   Parallelism: 4 lanes
   Tag length: 32 bytes
   Password[32]: 01 01 01 01 01 01 01 01
                 01 01 01 01 01 01 01 01
                 01 01 01 01 01 01 01 01
             01 01 01 01 01 01 01 01
   Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
   Secret[8]: 03 03 03 03 03 03 03 03
   Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04
   Pre-hashing digest: ec a9 db ff fa c9 87 5c
                       d2 dc 32 67 cb 82 7f 48
               79 af db 2f 6c b3 a5 29
               c5 87 7c 60 7d 72 92 02
               7c 23 15 47 fc 64 4f b8
               81 16 1f ee f6 e2 b3 d1
               63 49 1a 98 e8 a8 8c 8a
               40 15 b8 b5 dc 85 ec 1b

    After pass 0:
   Block 0000 [  0]: 7ddae3a315a45d2d
   Block 0000 [  1]: 50d8b9a49514a996
   Block 0000 [  2]: d5fd2f56c5085520
   Block 0000 [  3]: 81fa720dcf94e004
   ...
   Block 0031 [124]: 40b2d44e241f7a2a
   Block 0031 [125]: 9b9658c82ba08f84
   Block 0031 [126]: 917242b2a7a533f2
   Block 0031 [127]: 4169db73ebcc9e9c

    After pass 1:
   Block 0000 [  0]: a8daed017254d662
   Block 0000 [  1]: 1564d0fc4f5d07f4
   Block 0000 [  2]: 6a18ece1fd7d79ff
   Block 0000 [  3]: d04eb389a8ac7324
   ...



Biryukov, et al.           Expires May 8, 2016                  [Page 8]

Internet-Draft                   Argon2                    November 2015


   Block 0031 [124]: c859e8ba37e79999
   Block 0031 [125]: 0bb980cfe6552a4d
   Block 0031 [126]: 300cea2895f4459e
   Block 0031 [127]: 37af5d23a18f9d58

    After pass 2:
   Block 0000 [  0]: e86fc8e713dbf6d3
   Block 0000 [  1]: b30f1bdf8b4219d6
   Block 0000 [  2]: a84aec198d1eaff0
   Block 0000 [  3]: 1be35c5c8bfc52e0
   ...
   Block 0031 [124]: 9ffab191789d7380
   Block 0031 [125]: 4237012fc73e8d3e
   Block 0031 [126]: fbea11160fe7b50e
   Block 0031 [127]: 692210628c981931

   Tag: 57 b0 61 3b fd d4 13 1a
        0c 34 88 34 c6 72 9c 2c
        72 29 92 1e 6b ba 37 66
        5d 97 8c 4f e7 17 5e d2

6.2.  Argon2i Test Vectors

   =======================================Argon2i
   Memory: 16 KiB
   Iterations: 3
   Parallelism: 4 lanes
   Tag length: 32 bytes
   Password[32]: 01 01 01 01 01 01 01 01
                 01 01 01 01 01 01 01 01
                 01 01 01 01 01 01 01 01
             01 01 01 01 01 01 01 01
   Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
   Secret[8]: 03 03 03 03 03 03 03 03
   Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04
   Pre-hashing digest: c0 4e 5c 19 98 fc b1 12
                       09 3e 36 a0 76 3e 2f 95
               57 f2 cf 53 6f b8 89 c9
               9c c6 d8 cd b3 49 cd 0c
               9d 48 db cc 94 57 59 8c
               6c 2d a1 e1 d1 8b 3b aa
               7a 37 43 cb d1 7a d8 5c
               61 df dc 7e 7a 8e 64 2f

    After pass 0:
   Block 0000 [  0]: 34e7ba2a71020326
   Block 0000 [  1]: 3a4e252bf033a4cb
   Block 0000 [  2]: 3fb8e27bb8ab6a2b



Biryukov, et al.           Expires May 8, 2016                  [Page 9]

Internet-Draft                   Argon2                    November 2015


   Block 0000 [  3]: 65bb946635366867
   ...
   Block 0031 [124]: 433d8954deddd5d6
   Block 0031 [125]: c76ead72f0c08a23
   Block 0031 [126]: b7c6ce1154c1fdd1
   Block 0031 [127]: 0e766420b2ee181c

    After pass 1:
   Block 0000 [  0]: 614a404c54646531
   Block 0000 [  1]: 79f220080bfac514
   Block 0000 [  2]: e9da047d0e4406b4
   Block 0000 [  3]: 0995bc6d95590353
   ...
   Block 0031 [124]: 9b89e743afa7b916
   Block 0031 [125]: 9b3f7ca7cfff2db9
   Block 0031 [126]: 0065ff067978eab8
   Block 0031 [127]: 0a78fa2cea2b8bb2

    After pass 2:
   Block 0000 [  0]: 3fea10517d1a7476
   Block 0000 [  1]: e44c8bece4b3ecb2
   Block 0000 [  2]: e348b27d988671cb
   Block 0000 [  3]: 5f7f7cd33ef59e4d
   ...
   Block 0031 [124]: f60cb937689b55f8
   Block 0031 [125]: 418c55d7f343df3f
   Block 0031 [126]: 26899dd11adc7474
   Block 0031 [127]: dd3afa472ff1d124
   Tag: 91 3b a4 37 68 5b 61 3c
        f1 2b 94 46 79 53 40 37
        ac 46 cf a8 8a 02 f6 c7
        ba 28 0e 08 89 40 19 f2



"""
Author: 
Zelong Wang
Sun Yat-sen University
wangzelong2007@gmail.com
wangzelong@me.com

Programming With TrouSerS
=========================

1. These source code are based on "Programming With TrouSerS" by David Challener, in which the source code have many errors. I fix the wrong code,so code in this repo can run correctly.

2. Prerequisite
 (1)Please install linux kernel with TPM driver
 (2)If you don't have tpm chip on the motherboard,install a tpm-emulator
 (3)Install TrouSerS

3. Compile
  gcc sample.c -o sample -ltspi -Wall

4. Run
 (1)tpm must be started 
 (2)tcsd must be started
 (3)tpm takeownership -z make the SRK well known form(20 bytes with 0)




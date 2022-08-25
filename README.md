# Kenwood AHRP / ARCP KNS (Kenwood Network System) protocol

An effort in reverse engineering the KNS system protocol used for ARCP-590G for the Kenwood TS-590SG.

Wireshark & tools such as hercules are used to compare the KNS TCP packet contents up against CAT commands.

References:

* [Kenwood TS-590SG PC Command Reference](https://www.kenwood.com/i/products/info/amateur/pdf/ts_590_g_pc_command_e.pdf)

Kenwood uses ASCII, where `0x00-0x1f` are control codes, and `;` is the terminator .

## The ARCP Client

The ARCP-590G client can connect over USB / serial or through KNS (Kenwood Network System), KNS is basically Serial over TCP/IP.

The encoding is UTF-16LE, which is why the hex dumps below have 00 bytes padded..
ARCP and ARVP / ARHP use UTF-16LE.


**ARCP connecting to dummy serial (no radio):**
```
;;;
TC 1;         <-- Unknown command, guess this is Client Connect (radio doesn't respond to TC commands)
;;;ID;;;ID;;;;
TC 1;
;;;ID;;;ID;;;;
TC 1;
;;;ID;;;ID;;;;
TC 1;
;;;ID;;;ID;;;;
TC 1;
;;;ID;;;ID;   <-- timeout window reached here
```

* The `TC 1` command is unknown; not found in any documentation, possibly connect command or some sort of timeout / timer?
* It seems to send `;` as a part of a preamble or wakeup?


**Client connect process, radio response:**
```
PS0;ID023;PS0;ID023;
```

* Only responds to `ID;` in `PS0` power state, repeats `PS0` forever.
* `AI;` = "Auto Information", will make the radio output the results of changes automatically.

E.g: changing VFO frequency, once a change is detected if call `IF;`
ARCP will complain that the baud rate is wrong or doesn't identify the radio properly if `ID;` isn't responded to properly.*

### ARCP "590SG Connect & Power ON" sequence (some of this is edited to make it easier to read)

```
ID023;    // Version
AI0;      // Auto Information, initial state is off
FV1.04;   // FW version

MF0;      // Sets and Reads Menu A or B, in this case it means, use bank A for Menu items.

// Read menu items (0-99):
EX01400001;  EX01600005;  EX01700002;  EX018000001; 
EX019000003; EX02000000;  EX02100001;  EX02700000; 
EX02800000;  EX02900000;  EX03600001;  EX03700006; 
EX05400000;  EX05600000;  EX06100001;  EX06900001; 
EX07000001;  EX08500001;  EX01400001;  EX01600005; 
EX01700002;  EX018000001; EX019000003; EX02000000; 
EX02100001;  EX02700000;  EX02800000;  EX02900000; 
EX03600001;  EX03700006;  EX05400000;  EX05600000; 
EX06100001;  EX06900001;  EX07000001;  EX08500001; 

TS0;
FR0;  // Sets or reads VFO A (we're in frequency mode not memory mode) 
MD2;  // Recall or read operating mode, 2 is USB. This command will echo back confirming mode 
(Interesting tidbit: `MK` command exists, but why, seems to be panel only?)

IF00028074000      000000051020000080; 

SM00007; 

XI000280740002000; 
RI000280740002000; 
XI000280740002000; 
RI000280740002000; 
XI000280740002000; 
RI000280740002000; 

SM00006; SL00; SH07; GC1; SL00; SH07; GC1; SL00; SH07; GC1; DA0; SC00; AC010; 
AG0000; AN200; BC0; BP020; BY10; CR0; CT0; 

FA00028074000; FB00024907000; 

FL1; FS0; FT0; GC1; 
IF00028074000      000000051020000080; 

KS023; LK00; LM00000; MC 51; ME000; MG017; 
MR0 5100021074000210080800000000000000000; 
MR1 5100028074000210080800000000000000000; 

NB2; NR0; NT00; PA10; PB0000; PC100; PR1; QR00; RA0000; RG224; RM10000; RM20000; RM30000; 
RS0; RT0; SH07; SL00; SM00006; SP0; SQ0000; TO0; TP005; TYK 00; VX0; 
XI000280740002000; XO000000000000; 
XT0; CD00; VR0; 
RI000280740002000;
XI000280740002000; 
CT0; TO0; ID023; 
SH07; SL00; 
XI000280740002000; XI000280740002000; 
RI000280740002000; 
MR0 5100021074000210080800000000000000000; MR1 
5100028074000210080800000000000000000;
SL00; SH07; GC1; SL00; SH07; GC1; SM00005; PS1; TYK 00; 
```

---

### Authentication process

####TCP:
The KNS is quite simple, username & password is sent in cleartext.
The authentication sequence is (per ARCP):

```
"@ @ I D ;",
"@ @ F V ;",
"U I D : U S E R ;", <-- Not a CAT command
"P W D : P a s s w o r d ;" <-- Not a CAT command
```
Authentication commands are ignored by the radio?

#### Keep Alive sequence:

The `PS;` command is used as a keepalive, possibly in with ` AI;`
This is necessary to avoid the TCP or serial connection from being closed.

When (on) and idle the radio will simply repeat (over serial):
```
PS1; AI0;? ;?; PS1; AI0;? ;?; PS1; AI0; ?; ?; PS1; AI0;? ;?;
```
---

#### CW Keying & CW functions:

Per the Kenwood TS-590SG Command reference the KY command needs a fixed sized buffer:
>Parameter P2 has a fixed length of 24 bits. Characters that are
>left blank will be filled with spaces, but these spaces will not be
>converted to morse code

#### Commands executed through ARCP & sniffed with Wireshark:

CW "Auto Tune" (CA command):
```hexdump
0000   d0 37 45 a3 99 51 5c 6a 80 35 d7 34 08 00 45 38   .7E..Q\j.5.4..E8
0010   00 30 61 9c 40 00 74 06 a0 1e 59 09 a1 9b 0a 00   .0a.@.t...Y.....
0020   00 31 0f a2 f0 a1 71 b5 db 87 99 75 b8 9a 50 18   .1....q....u..P.
0030   02 01 19 5c 00 00 43 00 41 00 31 00 3b 00         ...\..C.A.1.;.
```

^ We receive `CA0;` back from ARHP once a singal has been found.

TX0 command:
```hexdump
0000   d0 37 45 a3 99 51 5c 6a 80 35 d7 34 08 00 45 38   .7E..Q\j.5.4..E8
0010   00 30 4c 36 40 00 74 06 b5 84 59 09 a1 9b 0a 00   .0L6@.t...Y.....
0020   00 31 0f a2 f0 a1 71 b5 a3 db 99 75 95 d0 50 18   .1....q....u..P.
0030   01 fd 4c d6 00 00 54 00 58 00 30 00 3b 00         ..L...T.X.0.;.
```
Pressing one of the memories in ARCP to key executes the `KY;` command
```hexdump
0000   5c 6a 80 35 d7 34 d0 37 45 a3 99 51 08 00 45 00   \j.5.4.7E..Q..E.
0010   00 2e ea 63 40 00 80 06 0b 91 0a 00 00 31 59 09   ...c@........1Y.
0020   a1 9b f0 a1 0f a2 99 75 95 26 71 b5 9f 5d 50 18   .......u.&q..]P.
0030   03 fe 87 ff 00 00 4b 00 59 00 3b 00               ......K.Y.;.
```

Example: KY Keying sequence, `5NN TU`: `0x4b = K 0x59 = Y 0x35 = 5 0x4e = N 0x54 = T 0x53 = U`

```hexdump
 0000   5c 6a 80 35 d7 34 d0 37 45 a3 99 51 08 00 45 00   \j.5.4.7E..Q..E.
 0010   00 60 d0 32 40 00 80 06 25 90 0a 00 00 31 59 09   .`.2@...%....1Y.
 0020   a1 9b f0 a1 0f a2 99 75 6e 6c 71 b5 60 5f 50 18   .......unlq.`_P.
 0030   04 01 f3 7e 00 00 4b 00 59 00 20 00 35 00 4e 00   ...~..K.Y. .5.N.
 0040   4e 00 20 00 54 00 55 00 20 00 20 00 20 00 20 00   N. .T.U. . . . .
 0050   20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00    . . . . . . . .
 0060   20 00 20 00 20 00 20 00 20 00 20 00 3b 00          . . . . . .;.
 ```
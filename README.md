# p2-advanced

### packet sniffing program

**to install and use the project, follow bellow steps:**
1. clone the project
2. install dependencies : **$ sudo apt-get install libpcap**
3. build and run the program with "SUDO" privilages:

    **$ gcc capture.c -o capture.o -lpcap**

    **$ sudo ./capture.o**

### this program captures HTTP packets witch goes over '127.2.3.4' - port 8000
you can use the custom client-server program (written in python 3) to test the C program.

### update: now capturing DNS packets too.
### update: now hijacking sessions.
### update: now reports all ip packets data.

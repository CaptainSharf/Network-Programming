all: A.out B.out C.out

A.out: A.c
	gcc -Wall A.c -lpcap -o A.out

B.out: B.c
	gcc -Wall B.c -lpcap -o B.out

C.out: C.c
	gcc -Wall C.c -lpcap -o C.out

clean:
	-@rm *.out 2>/dev/null || true

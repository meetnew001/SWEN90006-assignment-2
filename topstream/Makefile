SHELL:=/bin/bash

normal:
	gcc -g -o topstream topstream.c
	gcc -g -o service service.c

gcov:
	gcc -fprofile-arcs -ftest-coverage -g -o topstream-gcov topstream.c

fuzzing:
	afl-clang-fast -g -o topstream-fuzz topstream.c

asan:
	clang -fsanitize=address -g -o topstream-asan topstream.c

all: normal gcov asan fuzzing

clean:
	rm -f service topstream topstream-gcov topstream-fuzz topstream-asan topstream.gcno topstream.gcda

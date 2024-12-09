rm filesys.dsk
pintos-mkdisk filesys.dsk --filesys-size=8
pintos -- -f -q

# binary file
pintos -p ../../examples/big-stack -a big-stack -- -q
pintos -p ../../examples/cat -a cat -- -q   # read the content of a file
pintos -p ../../examples/echo -a echo -- -q   # read the content of a file
pintos -p ../../examples/crrm -a crrm -- -q
pintos -p ../../examples/fio -a fio -- -q
pintos -p ../../examples/fio2 -a fio2 -- -q
pintos -p ../../examples/telseek -a telseek -- -q
pintos -p ../../examples/zombie -a zombie -- -q
pintos -p ../../examples/big_array -a big_array -- -q

# text file 
pintos -p ../../examples/echo.c -a echo.c -- -q
pintos -p ../../examples/empty.txt -a empty.txt -- -q
pintos -p ../../examples/fio.c -a fio.c -- -q
pintos -p ../../examples/word.txt -a word.txt -- -q

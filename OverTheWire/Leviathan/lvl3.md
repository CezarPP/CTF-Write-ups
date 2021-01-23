# Level 3
## We have a programs what prints a file as leviathan3, but doesn't let us print files that we (leviathan2) don't have access to
## We notice a call (using ltrace) to system("/bin/cat %s", our_file), which lets us inject a command through the filename
## We have to name our file "fila;bash" to get a shell and then call the program with ./printfile "fila;bash"


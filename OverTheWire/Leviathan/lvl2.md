# Level 2
## Using ltrace ./check to analyze the binary we notice a call to strcmp("wow", "sex") where "wow" is our string.
## So the correct password is "sex", which gives us a shell as leviathan2, so we are able to cat the pass from /etc/leviathan_pass/leviathan2


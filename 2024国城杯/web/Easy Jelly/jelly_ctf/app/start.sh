#!/bin/sh
echo 'flag{this_is_a_test_flag}' > /flag
chmod 444 /flag
java -jar /app/Jelly-0.0.1-SNAPSHOT.jar

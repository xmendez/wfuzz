# Wfuzz - The Web Bruteforcer


## Bit of history

This project was started by Carlos del Ojo and Christian Martorella back in 2006, and it was in actively development until version 1.4c.

In 2011 after the code being unchanged for various years, Xavier Mendez took over the project and became the maintainer and main developer of the tool, releasing versions 1.4d to 2.1. Christian Martorella has remained in the project as a collaborator, actively supporting new versions with suggestions, beta testing and minor code changes.

## What is this?

Wfuzz is a tool designed to  brutefore web applications, it's very flexible, it supports:
	
- Recursion (When doing directory discovery)
- Post data bruteforcing
- Header bruteforcing
- Output to HTML (easy for just clicking the links and checking the page, even with postdata!)
- Colored output 
- Hide results by return code, word numbers, line numbers, etc.
- Url encoding
- Cookies
- Multithreading
- Proxy support 
- All parameter fuzzing
- etc

It was created to facilitate the task in web applications assessments, it's a tool by pentesters for pentesters ;)

How does it works?
------------------

The tool is based on dictionaries or ranges, then you choose where you want to bruteforce just by replacing the value by the word FUZZ.

Check the README file for usage examples.

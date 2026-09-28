---
title: "tldr please summarise - DownUnderCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "easy", "sh", "base64", "subprocess", "downunderctf", "downunderctf-2024", "2024", "ctf-writeup"]
summary: "run this code for get flag or search on execution of any sh command or file"
source:
  name: "CTFtime writeup #39312"
  url: "https://ctftime.org/writeup/39312"
original_source: "https://cybersecctf.github.io/blog/?q=tldrpleasesummarise%20downunderctf2024"
ctf:
  name: "DownUnderCTF 2024"
  year: 2024
  challenge: "tldr please summarise"
---

## Metadata

- **CTF:** DownUnderCTF 2024
- **Task:** tldr please summarise
- **Author team:** Hopper's Roppers
- **CTFtime tags:** misc, easy, sh
- **CTFtime:** <https://ctftime.org/writeup/39312>
- **Original writeup:** <https://cybersecctf.github.io/blog/?q=tldrpleasesummarise%20downunderctf2024>

---
run this code for get flag or search on execution of any sh command or file  


```
    import re  
    import subprocess  
    import os  
    import blog
    
    
    
    def solve(file_path, search="DUCTF"):  
          
        command=""     
        if not os.path.isfile(file_path):  
            command=file_path  
        else:   
         # Read the command from the file  
         with open(file_path, 'r') as file:  
            command = file.read().strip()  
       
        # Append commands to save output to [temp.sh](http://temp.sh) and run strings on it  
        full_command = f"{command} > [temp.sh](http://temp.sh) && chmod +x [temp.sh](http://temp.sh) && strings [temp.sh](http://temp.sh)"  
          
          
          
        # Execute the full command and capture the output  
        result = subprocess.run(full_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    
    
    
    
        # Combine stdout and stderr to cover all output  
        combined_output = result.stdout + result.stderr
    
    
    
    
    
          
        results=[]  
        # Search for the search string in the command output  
        for line in     combined_output.splitlines() :   
         if search in line:  
            results.append(line)  
        if len(results)==0:  
            return f"Flag containing '{search}' not found in the command output."  
        else:  
            for x in  results:  
                 print(x)
    
    
    
    
    
    if __name__ == "__main__" :  
     # Example usage search on any command or execute of sh file  
     command = blog.set("curl -sL <https://pastebin.com/raw/ysYcKmbu> | base64 -d",1)  
     search = blog.set("DUCTF",2)
    
    
    
    
    
     print(solve(command,search))  
```

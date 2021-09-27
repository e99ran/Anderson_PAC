# Anderson_PAC.py
The Anderson PAC attack Implementation based on impacket and xan7r's decryptKerbTicket.py

The attack leverages PKINIT Kerberos, and described thoroughly in the full Paper (Hebrew).

The Scripts gets 3 parameters. 
- Computer account password for the host whom the ticket belongs.
- host service ticket for host we control, that of course been asked by our victim user. (kirbi or ccache format)
- ASReplay key. obtained with Rubeus askTGT in the PKINIT as_req-rep process. (encoded with base64)


Example:
        ./AndersonPAC.py -k 5c7ee0b8f0ffeedbeefdeadbeeff1eefc7d313620feedbeefdeadbeefafd601e -t host_1803pc.kirbi -r Wf+ltNtt8e1Y8jlgiQ9Kag==

![image](https://user-images.githubusercontent.com/68777428/134928651-9c43fd57-ba80-476b-8360-bcda62ecf327.png)

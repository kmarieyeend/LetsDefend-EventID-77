# LetsDefend SOC Analyst Path  
## SOC138 - Detected Suspicious Xls File  
### EventID: 77

Hello everyone! LetsDefend asked me to create a troubleshooting guide for this lab. While this isn’t the only way to approach it, this is the method I used to successfully complete and close the alert. I hope it proves helpful for anyone working through the lab!

<B>Step 1: </B>

Click investigate to get started! 

<img width="614" alt="Screenshot 2024-12-05 at 3 04 46 PM" src="https://github.com/user-attachments/assets/81bd5c6b-561e-4690-b054-9413da8f427c">

<B>Step 2: </B>

  Once redirected to the Monitoring page, click on the 'Investigation channel' to see the triggered alert from Event 77. (Mine will say this alert has been re-investigated as I have already completed the lab once.) 
  Here you will see the triggered alert with details from the alert that can guide you into investigating the event. 

  Let's look at the important information in the details. 
  - The event took place on March 13th at 8:20 PM
  - The rule that triggered the event was a suspicious XLS file
  - The source address was 172.16.17.56
  - The source host was Sofia
  - The file name was ORDER SHEET & SPEC.xlsm with the file hash "
7ccf88c0bbe3b29bf19d877c4596a8d4"
  - The event was allowed and the file was downloaded

  What do we know about XLS files? It is a file format used by Excel to store spreadsheet data. This format can pose a risk as it allows macros to be embedded in the file. Macros are are scripts or small programs that automate tasks in Excel. The file downloaded has an .xlsm extension. This extension is used by the newer XLSX format supposed to be more secure by storing macros in a seperate file with the .xlsm extension. 

  If a .xlsm file is downloaded and it contains a malicous macro, the macro can execute, and if the macro contains malicious code, the file could deliver a malicious paylaod to the host computer. This could lead to data breach, system disruption, or privelage escalation if not dealt with. 
  
  <img width="1283" alt="Screenshot 2024-12-05 at 10 12 28 AM" src="https://github.com/user-attachments/assets/638d2d9b-b0f2-4ab3-b327-3a73d0257bc0">

<B>Step 3: </B>

  While on the Event 77, you will open a case for the alert by clicking on the 'Create a Case' button. 
  <img width="853" alt="Screenshot 2024-12-05 at 10 16 34 AM" src="https://github.com/user-attachments/assets/e94f6bdf-36b8-4d5c-977a-e09596b0b20b">

<B>Step 4: </B>

  Click continue
<img width="1293" alt="Screenshot 2024-12-05 at 10 18 18 AM" src="https://github.com/user-attachments/assets/2ae371c9-0314-4f0d-b036-f4f61ef6c2eb">

<B>Step 5: </B>

  This will bring up the following screen. From here, rather than starting the playbook, you will want to first check the threat and see if we need to quarantine the machine. 

  Since the file has a possibility of containing malicious code, we should first check the hash against known databases of flagged files. To do this, we can use a website called [Virus Total](https://www.virustotal.com). This is a free website that provides tools for analyzing and detecting malicious content, including files, URLs, domains, and IP addresses. It aggregates results from multiple antivirus engines, URL scanners, and tools to offer a comprehensive view of potential threats.

  Once in Virus Total, we want to seach the hash "
7ccf88c0bbe3b29bf19d877c4596a8d4" from the event. It will bring up the following information: 

<img width="1413" alt="Screenshot 2024-12-05 at 1 16 53 PM" src="https://github.com/user-attachments/assets/507ebeb4-76ec-45cf-8f3f-782558f662d5">

If you scroll down to the code insights you will see the following information: 

<img width="1307" alt="Screenshot 2024-12-05 at 1 18 09 PM" src="https://github.com/user-attachments/assets/08f8c308-c6d1-4f9c-8b3b-ad33f94e1b18">

Going forward with the investifation we will come back to the code insights.

From the main tab (Detection) we can move to the other tabs to learn more about the malicious file. In the details tab, we can see the name of the file that was in the original event. 

<img width="1150" alt="Screenshot 2024-12-05 at 1 21 50 PM" src="https://github.com/user-attachments/assets/dbbe76e0-a42b-48b5-9f9c-c3936f67a201">

From the relations page, we can see there are two URLS that are connected to the hash. 

<img width="1207" alt="Screenshot 2024-12-05 at 1 23 10 PM" src="https://github.com/user-attachments/assets/6b7f1e2a-d767-4a13-bce9-673a6ca8e651">

We can also scroll down and see contacted domains/IP addresses. We will also come back to this later on. 

<img width="653" alt="Screenshot 2024-12-05 at 1 24 31 PM" src="https://github.com/user-attachments/assets/6dbec7ee-e5ff-445e-bc47-b40965b51155">

The behavior section shows sandbox reports of what the .xslm file was capable of doing. 

<img width="1123" alt="Screenshot 2024-12-05 at 1 26 36 PM" src="https://github.com/user-attachments/assets/b9a5812b-4cb9-4322-87ff-5932e42fe37b">

Also shown in this section IP traffic

<img width="358" alt="Screenshot 2024-12-05 at 1 27 01 PM" src="https://github.com/user-attachments/assets/a488095a-df04-4336-a5f7-45cc0dd18f0b">

<B>Step 6: </B>

At this point, we know the file was allowed to be downloaded to the source address with the source host name Sofia. We know the file is malcious from entering the hash on Virus Total. So our next step is to go contain the host to restrict further damage. We want to click 'Endpoint Security' tab and click the three lines to open all the host names. 

<img width="1430" alt="Screenshot 2024-12-05 at 1 29 40 PM" src="https://github.com/user-attachments/assets/062da172-ff48-4213-af23-d90ed4c2c899">

When we find Sofia, we need to open that endpoint. 

<img width="1402" alt="Screenshot 2024-12-05 at 1 30 53 PM" src="https://github.com/user-attachments/assets/31ec05e8-2dde-4368-bbd1-ef441bade788">

Here we can scroll down and see a Powershell process was enabled. If we go back to our code insights from Virus Total. We see that the macro uses 'ShellExecute' function to launch programs or access system resources. 

<img width="880" alt="Screenshot 2024-12-05 at 1 51 59 PM" src="https://github.com/user-attachments/assets/1f1700d5-1775-4126-bb32-d0b2ec5c36af">

<img width="671" alt="Screenshot 2024-12-05 at 1 34 31 PM" src="https://github.com/user-attachments/assets/2f4d95a3-1597-4b5a-99b3-431e453d3331">

Given this information, if we go to the terminal section on Sofia's page we see the Powershell execution. And then someone accessed the dir command that will show the files and directories in the current user. Then someone used the cd command to change the directory. 

<img width="879" alt="Screenshot 2024-12-05 at 1 52 53 PM" src="https://github.com/user-attachments/assets/6a79bc79-9d41-4ecb-9680-1f7cdce2cc3c">

<B>Step 7: </B>

From here we know the malicious process was executed. We need to quarantine the system by clicking contain then change. 

<img width="1020" alt="Screenshot 2024-12-05 at 1 37 16 PM" src="https://github.com/user-attachments/assets/0f255df1-e141-4d0c-9a22-76632f3befd4">

<B>Step 8: </B>

Since our host is now contained, and no further damage can occur, we can continue the investigation. In the log management tab, we want to search events from our source address in our event alert. The source address was 172.16.17.56. So We want to click on source address in 'interesting fields' and type in our source address of 172.16.17.56. This will bring up three events. 

  <img width="1283" alt="Screenshot 2024-12-05 at 12 49 24 PM" src="https://github.com/user-attachments/assets/87d38b3a-b70e-4f6b-ab2d-190e3b107355">

From these three events we can cross out the event on October 19th as this is prior to our event data of March 13th. The other two events we should investigate. 

<img width="778" alt="Screenshot 2024-12-05 at 12 51 07 PM" src="https://github.com/user-attachments/assets/bf303bd4-5821-4200-b2d8-ab0d99e0ad4e">

<img width="784" alt="Screenshot 2024-12-05 at 12 51 23 PM" src="https://github.com/user-attachments/assets/3503982b-d440-4897-b004-f8f39f0ceaed">

From the two logs we can see the destination address are the same (172.53.143.89) this IP address is trying to communicate to our source address (sofia's computer) through port 443 which is the HTTPS protocol. From here, we need to investigate the destination address. 

<B>Step 9: </B>

  From our Virus Total search on the hash, we can go to the Relations tab to see if our destination address matches anything on the contacted IP addresses. 

  <img width="622" alt="Screenshot 2024-12-05 at 1 42 31 PM" src="https://github.com/user-attachments/assets/9c9cae3f-b6ea-4f92-b47a-885cefc33c96">

  Here we can see the IP address 172.53.143.89 is on the contacted IP addresses. 

<B>Step 10: </B>

If we go to the Behavior tab, and scroll down to IP traffic, we can see our destination address is associated with port 443 and multiwaretecnologia.com.br 

<img width="365" alt="Screenshot 2024-12-05 at 1 44 20 PM" src="https://github.com/user-attachments/assets/bcf14299-a1e1-46c2-a959-3da9a352f79c">

<B>Step 11: </B>

Since we have gathered information for our investigation, we can go back and start our playbook for the event. 

<img width="984" alt="Screenshot 2024-12-05 at 1 53 54 PM" src="https://github.com/user-attachments/assets/c40c099a-5eba-4a9d-83f9-37da5b763833">

To define the threat indicator, we can go through our options. We know that since a powershell command was executed we can go with 'Unexpected services or applications' option. 

<img width="1010" alt="Screenshot 2024-12-05 at 1 54 17 PM" src="https://github.com/user-attachments/assets/b3b7870d-b3b6-4544-8310-30656efd1a37">

The next question asks us if the malware is quarnatined or clean. It was not quarantined

<img width="835" alt="Screenshot 2024-12-05 at 2 04 54 PM" src="https://github.com/user-attachments/assets/576cb466-7f49-4f56-941e-218ab3b51016">

The next step is asking if the malware was malicious. We found on VirusTotal that it was infact flagged as malicious. 

<img width="869" alt="Screenshot 2024-12-05 at 2 06 10 PM" src="https://github.com/user-attachments/assets/6775be78-aee4-44f6-ba0e-a5cc4d7f1d73">

The next question is asking if someone requested the C2. The C2 address is referring to  IP address or domain name of a server that a malicious actor uses to control infected machines. After infecting a system, malware typically communicates with the C2 server to receive commands or send stolen data.

We know from our investifation that the C2 was the destination address 172.53.143.89 is connected to the malicious file. In our log management we found that the IP address had contacted the infected host twice through port 443. So the C2 address was accessed. 

<img width="690" alt="Screenshot 2024-12-05 at 2 17 16 PM" src="https://github.com/user-attachments/assets/0dc4c1eb-2d98-435b-8e6d-7fe249457652">

It then asks us if we have quarantined the infected host Sofia. Which we have. 

<img width="673" alt="Screenshot 2024-12-05 at 2 18 14 PM" src="https://github.com/user-attachments/assets/3110c191-cbd1-41e9-9d85-59b33aaa8edf">

From here it asks us to add artifacts to the playbook. 

We can add the following artifacts that we found: 

<img width="658" alt="Screenshot 2024-12-05 at 2 21 21 PM" src="https://github.com/user-attachments/assets/e54ab1fd-801b-4b3e-a1d2-99669270120b">

Now we can add an analysis note

<img width="626" alt="Screenshot 2024-12-05 at 2 24 45 PM" src="https://github.com/user-attachments/assets/9196f3ba-3af3-4669-a8c1-c612e942faee">

We then confirm we want to finish the playbook 
<img width="671" alt="Screenshot 2024-12-05 at 2 24 57 PM" src="https://github.com/user-attachments/assets/232c1a7b-5892-4928-a8ea-5af31394a2c5">

<img width="440" alt="Screenshot 2024-12-05 at 2 25 23 PM" src="https://github.com/user-attachments/assets/41f62721-2a71-4e71-b563-08b791e144a3">

<B>Step 12: </B>

Continue to the monitoring page and click the check mark to close the alert
<img width="802" alt="Screenshot 2024-12-05 at 2 26 34 PM" src="https://github.com/user-attachments/assets/b53a4ef1-aa35-4550-8c53-d7b354b89b0e">

Next mark the event as a true positive and write a quick note regarding why it is a true positive. 
<img width="475" alt="Screenshot 2024-12-05 at 2 27 31 PM" src="https://github.com/user-attachments/assets/75a3cd56-e0dc-4aa5-8331-fed7e0bb8dca">

I hope this was able to help anyone struggling with this lab. If you have any questions regarding the steps I used, feel free to reach out to me via [LinkedIn](https://www.linkedin.com/in/kyeendperson/).

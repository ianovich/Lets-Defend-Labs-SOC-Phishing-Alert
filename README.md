# Lets-Defend-Labs-SOC-Phishing-Alert
## SOC114 - Malicious Attachment Detected - Phishing Alert

# Alert Triggered
 An alert was triggered for a phishing email detected with a malicious attachment and URL.
 
 ![Attachment 1](https://github.com/user-attachments/assets/1fc6bb17-fd52-4374-af32-df82327a8f50)

 ## Initial Considerations

- Before proceeding to the playbook, it's crucial to gather and verify several key details about the suspicious email. Start by determining the exact date and time when the email was sent to correlate with other logs. Identify the SMTP server address used for sending the email, as this helps trace its origin. Check the sender's email address to assess its legitimacy and verify the recipient's address to understand who was targeted. Evaluate the content of the email for any suspicious elements, such as urgent messages or unexpected attachments. Finally, confirm whether the email includes any attachments and analyze them for malicious content. Collecting these details provides a comprehensive understanding of the incident and ensures a more effective response in the playbook.

- The first thing was to go to richard's email and check if there was any attachment sent and who was the sender.
  
  ![Attachment 3](https://github.com/user-attachments/assets/7421765b-f1c1-4cfd-9288-5a0ab9cf8ab1)

 - The mail source address was accounting@cmail.carleton.ca and the destination address was richard@letsdefend.io

 - I utilzed virus total scan tool to give me more details on the hash file and it was found to be flagged malicious by 37 vendors
  
 ![virus total](https://github.com/user-attachments/assets/776f44d9-3a49-4afe-9d7c-368438f0339b)

- Scanned for the SMTP adress to determine its origin using AbuseIPDB.I found that SMTP address 49.234.43.39 is located in China. This adress has been reported a total of 2,399 times from 381 distinct sources. It was first reported on November 21, 2020, with the most recent report occurring 1 year ago.
 ![Abuse IDP](https://github.com/user-attachments/assets/71f3e5c2-3929-4aec-9aa1-72ad69faffee)

- I had to do a cross checking analysis on the SMTP address to check its activity,so i shifted to virus total and it was flagged again as malicious by 2 vendors

![china](https://github.com/user-attachments/assets/2c12e709-a822-4f49-ad2a-f9483c727a42)

- Having found the SMPTP to be suspicious,i decided to check the domain of the source email adress to check whether it was legitimate or not using AbuseIPDB
  
  ![canada](https://github.com/user-attachments/assets/447503a3-f60f-4d40-a4fa-2adf2e09dbb8)
  
- It turned out that the domain had no negative reports on it and it was infact was fro a school.In this case We identified that the SMTP address 49.234.43.39 sent an email disguised as coming from sender address to the recipient. The SMTP address, owned by a party in China, is flagged as malicious.

## We can resolve case on the Playbook
- The Playbook is a step-by-step guide for efficiently handling security incidents and threats.
  
![case 1](https://github.com/user-attachments/assets/3c17f5f4-bb35-4cd9-9888-67656695a597)

The was an attachment on the email.

![case2](https://github.com/user-attachments/assets/e9435cfc-a462-4b90-8937-2e4546955da0)

- The email indeed contained a malicious attachment flagged by virustotal.

![case3](https://github.com/user-attachments/assets/d5b81837-2970-4f66-afef-e5429de7ec76)

- The email was indeed delivered containing a potential harm to the host computer,and so action had to be taken.

![case5](https://github.com/user-attachments/assets/ce8511ab-6e66-4ed8-acbc-9811784306af)

![deleted](https://github.com/user-attachments/assets/cc4a58d8-527b-429a-b622-f0925a54b947)

- The email had to be deleted from the recepient's inbox not to escalate further damage to the computer. 

 ![snip](https://github.com/user-attachments/assets/35e66c76-d901-4da3-a993-2f555630e47d)
 
 - To check above i had to go to virus total to see whether there wer any relations with the hash file and i found two URLS related to the hash.

   ![c2 contacted](https://github.com/user-attachments/assets/823e99e9-a288-468c-80d9-9e152266e813)

 - After pasting the URL on the log page there was a local IP adress associated with it. While analyzing the log, I looked up the EDR's indicated source IP address, 172.16.17.45. 
   Richard has been assigned it. confirming that this is the machine we're looking for.
   
    ![contact11](https://github.com/user-attachments/assets/28b5fa06-252a-4ced-b501-4ab91066e2cc)

 - Below shows Richard's browser history matching the URL and time of activity
   
   ![browser richard](https://github.com/user-attachments/assets/903559d0-1bd2-4501-a6a5-49e95afce2c6)

- Richard's machine was contained to isolate them from the network and further investigation be carried out.
  ![contain richie](https://github.com/user-attachments/assets/f2495e7a-f896-48cb-80d3-5e01232637b0)

- We identified that an email was sent from a disguised sender address, to recipient address. The email contained a malicious PDF file, leading to the erasure of the user's email address. Richard's machine has been contained as a precaution because he opened the file, which caused damage to his system.
  
![important](https://github.com/user-attachments/assets/0bc1d549-9d8b-48d5-8acc-9626f5dfde2e)


 - After a deep dive into the investigation here are the results
 
 ![done](https://github.com/user-attachments/assets/8ed1965e-83b6-4b6c-a510-2e1134b49b18)

 




  








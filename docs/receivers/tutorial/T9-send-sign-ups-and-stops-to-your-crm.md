# T9 Send sign-ups and stops to your CRM

title: Send sign-ups and stops to your CRM
tagline: Connect a system, then let your automation tool update the CRM

| # | Do | Narration |
|---|----|-----------|
| 1 | click link "Connected systems" | Open Connected systems. ConsentVault sends a signed message every time a person signs up or says stop, and alerts you if your system does not accept it. What happens inside your system is yours. |
| 2 | click link "Connect a system" | Choose Connect a system. Name it, then paste the web address your automation tool gave you. It can be n8n or Make. |
| 3 | spot label "Endpoint address (https only)" | The address must start with https. Your automation tool shows it when you add its webhook step. |
| 4 | spot text "Signature" | Choose how messages are signed. A secret or public key is shown once after you connect. Copy it into your template. |
| 5 | spot text "Contact sent as" | Contact sent as decides who the message names, and nothing is preselected. Fingerprint only sends a scrambled reference, so a CRM cannot find the person. |
| 6 | spot text "Plain contact point" | To match a contact in your CRM, choose Plain contact point. It sends the phone number or email to a system you run, and you are responsible for how it stores and uses it. The choice is recorded in the audit log. |
| 7 | click link "Cancel" | Nothing else personal is sent. Choose Cancel to leave this demonstration without connecting anything. |
| 8 | show "assets/T9-diagram.png" | This is the whole path. ConsentVault sends one signed message for each sign-up or stop. Your automation checks the signature, finds the person in your CRM, and updates that contact. |
| 9 | show "assets/T9-n8n-1.png" | This is the n8n template. The first steps check the signature, skip test messages and repeats, and refuse a system set to Fingerprint only. |
| 10 | show "assets/T9-n8n-2.png" | Then it finds every contact that matches and updates only those with an older version. It never creates a contact. An optional alert in your own tool covers a stop for someone not in your CRM. |

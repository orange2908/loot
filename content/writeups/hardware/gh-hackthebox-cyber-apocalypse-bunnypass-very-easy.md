---
title: "BunnyPass [Very Easy] - cyber apocalypse 2024"
category: "hardware"
subcategory: "hardware"
type: "writeup"
tags: ["hardware", "bunnypass", "easy", "embedded", "bunnypass-very-easy", "cyber-apocalypse"]
summary: "14$^{st}$ March 2024 / Document No."
source:
  name: "hackthebox/cyber-apocalypse-2024"
  url: "https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/hw/BunnyPass%20%5BVery%20Easy%5D/README.md"
ctf:
  name: "cyber apocalypse"
  year: 2024
  challenge: "BunnyPass [Very Easy]"
---

## Source

- **CTF:** cyber apocalypse 2024
- **Challenge:** BunnyPass [Very Easy]
- **Repository:** [hackthebox/cyber-apocalypse-2024](https://github.com/hackthebox/cyber-apocalypse-2024)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/hw/BunnyPass%20%5BVery%20Easy%5D/README.md>

---
![img](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/banner.png)

<img src='https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/htb.png' align=left /><font 
size='6'>BunnyPass</font>

14$^{st}$ March 2024 / Document No. D24.102.24

Prepared By: `diogt`

Challenge Author(s): `makelaris`

Difficulty: <font color=green>Very Easy</font>

Classification: Official

# Synopsis

- The objective of this challenge is to gain access to a RabbitMQ instance and read the messages sent over it

## Description

- As you discovered in the PDF, the production factory of the game is revealed. This factory manufactures all the hardware devices and custom silicon chips (of common components) that The Fray uses to create sensors, drones, and various other items for the games. Upon arriving at the factory, you scan the networks and come across a RabbitMQ instance. It appears that default credentials will work.


## Skills Required

- Basic understanding of web interfaces

## Skills Learned

- Navigating a RabbitMQ instance and reading messages

# Enumeration

This challenge does not have a downloadable part, we are only given a live instance of  RabbitMQ. As per the description of the challenge, the default credentials should be valid for this instance. Given this hint let us try the common `admin:admin` combination.

![loginpage](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/hw/BunnyPass%20[Very%20Easy]/assets/loginpage.png)



After pressing the Login button we successfully connect to the RabbitMQ Instance.

![page_1](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/hw/BunnyPass%20[Very%20Easy]/assets/page_1.png)

If we search in Google for RabbitMQ we can see that it's a message broker, using the Message Queuing Protocol.

<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/hw/BunnyPass%20[Very%20Easy]/assets/rabbitmq.png" alt="rabbitmq" style="zoom:50%;" />

Based on that information we can navigate to the Queues tab and see if we can read any of the messages.

![queues2](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/hw/BunnyPass%20[Very%20Easy]/assets/queues2.png)

Out of all the Queues, only one appears to have a substantial number of messages, factory_idle with 6 messages ready. Selecting that leads us to another page.

![get_msg_1](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/hw/BunnyPass%20[Very%20Easy]/assets/get_msg_1.png)

On the bottom of the page, we can see a `Get messages` drop-down menu.

<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/hw/BunnyPass%20[Very%20Easy]/assets/get_msg_2.png" alt="get_msg_2" style="zoom:50%;" />

Let's input the number of messages we saw earlier, six, and hit the `Get Message(s` button. Scrolling over the messages we can see that the last message contains the flag.

<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/hw/BunnyPass%20[Very%20Easy]/assets/get_msg_3.png" alt="get_msg_3" style="zoom:50%;" />

# Solution

N/A

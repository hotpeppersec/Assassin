============
Introduction
============

.. image:: ../images/panw-logo-bw.png
   :align: center

Overview
   When an attacker looks at an organization as her target, 
   nearly every approach starts with reconnaissance. Gathering 
   information about the organization takes place in many ways, 
   but today’s attacker rarely does so in a way that can be 
   detected by most security tools. The purpose of this project 
   is to illustate a common technique that is easily automated 
   and rich in its ability to mine information, giving the 
   attacker a list of potential target devices.

Description
   Asassin was originally developed by Dan Ward of the Palo Alto
   Networks SecOps CE Team. It uses some scripting to assemble 
   the output of a few well known techniques (Hacker Target, Shodan)
   to gather information about the publicly registered devices of a
   target’s domain, search for known vulnerabilities associated 
   with those devices and matching up some descriptions of those
   vulnerabilities with CVE information. This gives the attacker a 
   view of what the target has and how those devices might be 
   attacked. From the attacker’s perspective, the key advantage 
   this approach is that from the target’s perspective, it is 
   completely silent and invisible. At no time during the process 
   does the attacker ever touch any resource that actually belongs 
   to the target.
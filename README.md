# CyberPatriot Scripts (Team 18-2405)
<p>This repository contains a series of automation scripts for the CyberPatriot competition. The intention of these scripts is to fortify an operating system with adequate and up-to-date cybersecurity configurations so as to secure points for the competition. Because of the density of the automation, these processes can save up to 30 minutes of work, replacing it with maybe 2 minutes of light file creation, organization, and execution.</p>

<p>Also Cisco notes maybe I guess</p>
<h3>Scripts by OS</h3>
<ul>
  <li>Windows</li>
  <ul>
    <li>Windows 10</li>
    <li>Windows 11</li>
    <li>Windows Server 2019</li>
    <li>Windows Server 2022</li>
  </ul>
  <li>Linux</li>
  <ul>
    <li>Ubuntu 22</li>
    <ul>
      <li><a href="Linux/cplinuxusers.sh">Users</a></li>
    </ul>
    <li>Ubuntu 24</li>
    <ul>
      <li><a href="Linux/cplinuxusers.sh">Users</a></li>
    </ul>
    <li>Mint 21</li>
    <ul>
      <li><a href="Linux/cplinuxusers.sh">Users</a></li>
    </ul>
  </ul>
</ul>

<h2>Guide by File</h2>
<p>Each program file in the repository (meaning excluding this one and PDFs/pictures) is documented below by alphanumeric order.</p>

<h3><a href="Linux/cplinuxusers.sh">cplinuxusers.sh</a></h3>
<p><i>Works for: Ubuntu 22, Ubuntu 24, Mint 21</i></p>
<br>
<p>This file is a Shell script which automates the creation, removal, privilege allocation, and password usage of a list of users and administrators. This is useful for the section of the competition where accounts are listed in the README. To use the script, follow the instructions below:</p>
<ol>
  <li>Download the file onto any folder you can access and remain in that directory.</li>
  <li>Create a new text file while in the same directory as the downloaded Shell file with the following command if you're using the terminal or by making a blank text file if you're using the GUI:
  
  ```shell
  sudo nano touch users.txt
  ```
  </li>
  <li>Create or copy a list containing all <i>non-privileged</i> users you want in the user group, separated by a newline, with no additional spaces, marks, or symbols.</li>
  <li>Create a second text file while in the same directory using the terminal (below) or GUI:
  
  ```shell
  sudo nano touch admins.txt
  ```
  </li>
  <li>Create or copy a list containing all <i>privileged administrators</i>, separated by a newline, with no additional spaces, marks, or symbols.</li>
  <li>Run the following in the terminal. If all the information presented looks correct, type "Y" when prompted and enter your sudo password if prompted.

  ```shell
  chmod +x cplinuxusers.sh
  ./cplinuxusers.sh users.txt admins.txt
  ```
  </li>
</ol>
<p><b>Note:</b> Do not be afraid that the program will erase the current or root user; I specifically programmed it not to do that. Also, if you need to refer to it again, write down the passwords it spits out for each account. If you forget, you can probably either look it up in the system anyway or run the program again, which will randomize and print the passwords to you again without making any changes to the user structure.</p>

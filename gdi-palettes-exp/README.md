# gdi-palettes-exp
DC25 5A1F - Demystifying Windows Kernel Exploitation by Abusing GDI Objects
https://www.defcon.org/html/defcon-25/dc-25-speakers.html#El-Sherei
https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/5A1F/

# Content:
Windows kernel exploitation is a difficult field to get into. Learning the field well enough to write your own exploits require full walkthroughs and few of those exist. This talk will do that, release two exploits and a new GDI object abuse technique.
We will provide all the detailed steps taken to develop a full privilege escalation exploit. The process includes reversing a Microsoft's patch, identifying and analyzing two bugs, developing PoCs to trigger them, turning them into code execution and then putting it all together. The result is an exploit for Windows 8.1 x64 using GDI bitmap objects and a new, previously unreleased Windows 7 SP1 x86 exploit involving the abuse of a newly discovered GDI object abuse technique.

## Detailed White-paper: 
5A1F_Defcon_25_Demystifying_Kernel_Exploitation_By_Abusing_GDI_Objects_white_paper.pdf
## DC25 Slides: 
5A1F_Defcon_25_Demystifying_Kernel_Exploitation_By_Abusing_GDI_Objects_slides_final.pdf

Windows 8.1 x64 MS16-098 EoP exploit.

Windows 7 SP1 x86 MS17-017 Eop exploit by abusing GDI Palette Objects (New technique).

# License
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](http://creativecommons.org/licenses/by-nc-sa/4.0/)

This project is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (http://creativecommons.org/licenses/by-nc-sa/4.0/) Permissions beyond the scope of this license may be available at http://sensepost.com/contact/.

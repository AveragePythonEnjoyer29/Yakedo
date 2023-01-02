# Yakedo
An unfinished, proof of concept peer to peer network i wrote for fun! <br>
I wrote it so i could familiarize myself with peer to peer networks, sockets and a tiny bit of blockchain technology (public key cryptography and the proof-of-work module) <br>
It was a fun project, and i learned a lot of new stuff!

# Features
- Strong encryption (XChaCha20Poly1305)
- Proof-of-work system (need to complete a challenge in order to jon the network, uses SHA512)
- Uses public-key cryptography (using Diffie-Hellman with Curve448)
- Owner messages are signed using EdDSA with (again) Curve448
- Payloads are padded with random data

# Cons
- Network is very bandwith heavy, due to it being a **gossip style network**
- Still unfinished, so it needs some work before it's done (perhaps a feature?)

# Authors note
The code is unfinished! I decided to stop working on it because i was losing motivation, and was more interested in other projects. <br>
Feel free to poke around the code, perhaps even open an pull request.

# Resources
Here are some resources i used while developing this project. <br>
Maybe they're useful to you!
- proof of work:
    - https://github.com/anders94/blockchain-demo
    - https://www.lrb.co.uk/the-paper/v41/n08/donald-mackenzie/pick-a-nonce-and-try-a-hash
    - https://bitcointalk.org/index.php?topic=2345.msg31405#msg31405
- the logic
    - https://github.com/ahmedfarou22/P2P-ecrypted-caht-room (not really a clear example, but i used the logic of the code for my project)

# License
```
This project is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, 
either version 3 of the License, or (at your option) any later version.

This project is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this code. 
If not, see <https://www.gnu.org/licenses/>. 
```
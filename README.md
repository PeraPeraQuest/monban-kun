# monban-kun
Authentication and Login Specialist

## Motivation
門番くん (monban-kun) is a Discord authentication utility microservice for
PeraPera Quest.

PeraPera Quest needs to identify the person connecting to play the game,
in order to know what language instruction should be given next.

A typical solution to the problem is a browser cookie. Unfortunately these
are somewhat fragile (likely to be cleared or lost) and non-trivial to sync
between devices.

Another solution is an account system; PeraPera Quest would allow the user
to choose a username and password. This comes with all the downsides of an
account system; forgotten passwords, stolen passwords, forgotten usernames
that lead to multiple accounts, etc.

A user might think, 'Wouldn't it be awesome if I could just log in with my
Discord account?' And fortunately, enough users have thought that; that
solution already exists and is called OAuth2.

PeraPera Quest tells the user: "Go to Discord and tell them PeraPera Quest
wants to see your Discord ID."

The user goes to Discord, and Discord asks: "Are you sure you want PeraPera
Quest to see your Discord ID?"

The user clicks the button to authorize it, and Discord says: "Okay, go back
to PeraPera Quest and give them this code. I'll let them ask me about your
Discord ID."

All the problems solved. PeraPera Quest doesn't need to maintain accounts,
or have to deal with any lost/stolen accounts or passwords. The user doesn't
need to remember yet another account, and can log in easily using Discord.

Monban-kun does this work. It implements the "Log-In with Discord" part of
PeraPera Quest.

## License
monban-kun  
Copyright 2025 Patrick Meade.  

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

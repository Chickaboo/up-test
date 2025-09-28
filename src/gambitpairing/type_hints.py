"""Type hints used in Gambit Pairing."""

from typing import List, Literal, Optional, Tuple

# chess colours
W = Literal["White"]
B = Literal["Black"]
# Basically, white or black
Colour = Literal[W, B]


# List of players
Players = List["Player"]
# Tuple of player indices in Players
MatchPairing = Tuple[int, int]
# All pairings for one round
RoundSchedule = Tuple[MatchPairing, ...]
# A Tuple containing
Pairings = Tuple[List[Tuple["Player", "Player"]], Optional["Player"]]
MaybePlayer = Optional["Player"]

#  LocalWords:  MatchPairing RoundSchedule

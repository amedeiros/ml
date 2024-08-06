from enum import Enum

PLAYER_X_TOKEN = "X"
PLAYER_X_VALUE = 1
PLAYER_O_TOKEN = "O"
PLAYER_O_VALUE = 2

PLAYER_X_WIN_TOTAL = PLAYER_X_VALUE * 3
PLAYER_O_WIN_TOTAL = PLAYER_O_VALUE * 3

PLAYER_TOKEN_TO_VALUE = {
    PLAYER_X_TOKEN: PLAYER_X_VALUE,
    PLAYER_O_TOKEN: PLAYER_O_VALUE,
}

PLAYER_VALUE_TO_TOKEN = {
    PLAYER_X_VALUE: PLAYER_X_TOKEN,
    PLAYER_O_VALUE: PLAYER_O_TOKEN,
}

# Board layout
# A | B | C
# D | E | F
# G | H | I
POSITIONS = {
    "A": (0, 0),
    "B": (0, 1),
    "C": (0, 2),
    "D": (1, 0),
    "E": (1, 1),
    "F": (1, 2),
    "G": (2, 0),
    "H": (2, 1),
    "I": (2, 2),
}

POSITIONS_TO_TOKEN = {
    (0, 0): "A",
    (0, 1): "B",
    (0, 2): "C",
    (1, 0): "D",
    (1, 1): "E",
    (1, 2): "F",
    (2, 0): "G",
    (2, 1): "H",
    (2, 2): "I",
}


class GameState(Enum):
    X_WON = 1
    O_WON = 2
    DRAW = 3
    NOT_ENDED = 4

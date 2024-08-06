from typing import List, Tuple
import os
import numpy as np
from constants import (
    POSITIONS,
    PLAYER_TOKEN_TO_VALUE,
    GameState,
    PLAYER_X_VALUE,
    PLAYER_O_VALUE,
    PLAYER_VALUE_TO_TOKEN,
)


class Board:
    _board: List[List[int]]
    _playable_locations: List[Tuple[int, int]]

    def __init__(self):
        self.reset()

    def reset(self):
        self._board = np.zeros([3, 3]).astype(int)
        self._playable_locations = list(POSITIONS.values())

    def get_board(self):
        return self._board

    def set_board(self, board):
        self.board = board

    def get_playable_locations(self):
        return self._playable_locations

    def position_filled(self, position: str) -> bool:
        return self._board[POSITIONS[position]] != 0

    def get_position(self, position: str):
        return self._board[POSITIONS[position]]

    def play_position(self, position: str, player: str):
        if self.position_filled(position):
            raise RuntimeError("Poisition taken!")

        location = POSITIONS[position]
        self._board[location] = PLAYER_TOKEN_TO_VALUE[player]
        self._playable_locations.remove(location)

    def display(self):
        self._screen_clear()
        print(f"| {self._empty_token_or_player_token('A')} | {self._empty_token_or_player_token('B')} | {self._empty_token_or_player_token('C')} |")
        print(f"| {self._empty_token_or_player_token('D')} | {self._empty_token_or_player_token('E')} | {self._empty_token_or_player_token('F')} |")
        print(f"| {self._empty_token_or_player_token('G')} | {self._empty_token_or_player_token('H')} | {self._empty_token_or_player_token('I')} |")

    def _screen_clear(self):
        # for mac and linux(here, os.name is 'posix')
        if os.name == 'posix':
            _ = os.system('clear')
        else:
            # for windows platfrom
            _ = os.system('cls')

    def _empty_token_or_player_token(self, empty_token: str):
        position = self.get_position(empty_token)

        if position == 0:
            return empty_token

        return PLAYER_VALUE_TO_TOKEN[position]

    def state(self):
        # Some numpy magic: https://stackoverflow.com/questions/46802651/check-for-winner-in-tic-tac-toe-numpy-python
        # Check O
        O_MASK = self._board == PLAYER_O_VALUE
        o = O_MASK.all(0).any() | O_MASK.all(1).any()
        o |= np.diag(O_MASK).all() | np.diag(O_MASK[:, ::-1]).all()

        if o:
            return GameState.O_WON

        # Check X
        X_MASK = self._board == PLAYER_X_VALUE
        x = X_MASK.all(0).any() | X_MASK.all(1).any()
        x |= np.diag(X_MASK).all() | np.diag(X_MASK[:, ::-1]).all()

        if x:
            return GameState.X_WON

        # Check Draw
        if 0 not in self._board:
            return GameState.DRAW

        return GameState.NOT_ENDED

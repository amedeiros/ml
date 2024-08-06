from player import Human, RandomAI
from constants import PLAYER_X_TOKEN, PLAYER_O_TOKEN, GameState
from board import Board


class Game:
    def __init__(self, player_x=Human(PLAYER_X_TOKEN), player_o=RandomAI(PLAYER_O_TOKEN), verbose=True, board=Board()):
        self.player_X = player_x
        self.player_O = player_o
        self.board = board
        self.verbose = verbose

    def play(self):
        while self.board.state() == GameState.NOT_ENDED:
            # Print before X's turn
            self.display_board()

            # X Goes first
            self.player_X.turn(self.board)

            # Print after X's turn
            self.display_board()

            # Check the state
            if self.board.state() != GameState.NOT_ENDED:
                break

            # Player O Turn
            self.player_O.turn(self.board)

        # Print end board
        self.display_board()

    def display_board(self):
        if self.verbose:
            self.board.display()

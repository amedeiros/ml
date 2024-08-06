from abc import ABC, abstractmethod
from board import Board
from constants import POSITIONS_TO_TOKEN, GameState, PLAYER_X_VALUE, PLAYER_O_VALUE, PLAYER_O_TOKEN, PLAYER_X_TOKEN
import numpy as np
import pickle
import random


class Player(ABC):
    token: str

    def __init__(self, token: str):
        self.token = token

    @abstractmethod
    def turn(self, board: Board):
        pass


class Human(Player):
    def turn(self, board: Board):
        v = None

        while v is None:
            v = input(f"Enter position player {self.token}: ").upper()
            if board.position_filled(v):
                print(f"Position {v} is already taken!")
                v = None

        board.play_position(v, self.token)


class RandomAI(Player):
    def turn(self, board: Board):
        locations = board.get_playable_locations()
        loc_len = len(locations)
        idx = np.random.randint(0, loc_len)
        loc = locations[idx]
        v = POSITIONS_TO_TOKEN[loc]

        board.play_position(v, self.token)


# Utility function
def state(game_board):
    # Some numpy magic: https://stackoverflow.com/questions/46802651/check-for-winner-in-tic-tac-toe-numpy-python
    # Check O
    O_MASK = game_board == PLAYER_O_VALUE
    o = O_MASK.all(0).any() | O_MASK.all(1).any()
    o |= np.diag(O_MASK).all() | np.diag(O_MASK[:, ::-1]).all()

    if o:
        return GameState.O_WON

    # Check X
    X_MASK = game_board == PLAYER_X_VALUE
    x = X_MASK.all(0).any() | X_MASK.all(1).any()
    x |= np.diag(X_MASK).all() | np.diag(X_MASK[:, ::-1]).all()

    if x:
        return GameState.X_WON

    # Check Draw
    if 0 not in game_board:
        return GameState.DRAW

    return GameState.NOT_ENDED


class MinMaxAI(Player):
    game_board = None
    corners = [(0, 0), (0, 2), (2, 0), (2, 2)]

    def turn(self, board: Board):
        self.game_board = np.copy(board.get_board())

        # First turn corner strategy improves overall speed if AI is first
        if PLAYER_X_VALUE not in self.game_board and PLAYER_O_VALUE not in self.game_board:
            idx = np.random.randint(0, 4)
            corner = self.corners[idx]
            pos = POSITIONS_TO_TOKEN[corner]
            board.play_position(pos, self.token)
            return

        x = None
        y = None

        if self.token == PLAYER_O_TOKEN:
            _, x, y = self._max_agent(-2, 2)
        else:
            _, x, y = self._min_agent(-2, 2)

        v = POSITIONS_TO_TOKEN[(x, y)]
        board.play_position(v, self.token)

    # Player O Is max
    def _max_agent(self, alpha, beta):

        # We're initially setting it to -2 as worse than the worst case:
        maxv = -2
        px = None
        py = None

        current_state = state(self.game_board)

        if current_state == GameState.X_WON:
            return (-1, 0, 0)
        elif current_state == GameState.O_WON:
            return (1, 0, 0)
        elif current_state == GameState.DRAW:
            return (0, 0, 0)

        for i in range(0, 3):
            for j in range(0, 3):
                if self.game_board[i, j] == 0:
                    # On the empty field player 'O' makes a move and calls Min
                    # That's one branch of the game tree.
                    self.game_board[i, j] = PLAYER_O_VALUE
                    m, _, _ = self._min_agent(alpha, beta)
                    # Fixing the maxv value if needed
                    if m > maxv:
                        maxv = m
                        px = i
                        py = j
                    # Setting back the field to empty
                    self.game_board[i, j] = 0

                    if maxv >= beta:
                        return (maxv, px, py)

                    if maxv > alpha:
                        alpha = maxv

        return (maxv, px, py)

    # Player X is min
    def _min_agent(self, alpha, beta):
        # Possible values for minv are:
        # -1 - win
        # 0  - a tie
        # 1  - loss

        # We're initially setting it to 2 as worse than the worst case:
        minv = 2
        qx = None
        qy = None

        current_state = state(self.game_board)

        if current_state == GameState.X_WON:
            return (-1, 0, 0)
        elif current_state == GameState.O_WON:
            return (1, 0, 0)
        elif current_state == GameState.DRAW:
            return (0, 0, 0)

        for i in range(0, 3):
            for j in range(0, 3):
                if self.game_board[i, j] == 0:
                    self.game_board[i, j] = PLAYER_X_VALUE
                    m, _, _ = self._max_agent(alpha, beta)
                    if m < minv:
                        minv = m
                        qx = i
                        qy = j
                    self.game_board[i, j] = 0

                if minv <= alpha:
                    return (minv, qx, qy)

                if minv < beta:
                    beta = minv

        return (minv, qx, qy)


# Base class for AI that requires learning
class LearningPlayerAI(Player):
    @abstractmethod
    def learn(self):
        pass


class QLearningAI(LearningPlayerAI):
    Q = {}
    alpha = 0.9
    gamma = 0.75
    eps = 1

    def __init__(self, token: str):
        super().__init__(token)
        self.Q = pickle.load(open("Q-X.pkl", "rb"))
        # print("Learning...")
        # self.learn()

    def turn(self, board):
        best = self.get_best_action(str(board.get_board()))

        if best is None:
            _, best = self._random_move(board)

        board.play_position(POSITIONS_TO_TOKEN[best], self.token)

    def learn(self):
        for _ in range(30_000):
            self._learn_one_game()
            self.eps -= 0.0001

        file = open('Q.pkl', 'wb')
        # dump information to the file
        pickle.dump(self.Q, file)

    def get_best_action(self, state):
        keys = list(self.Q.get(state, {}).keys())

        if not keys:
            return None

        if self.token == PLAYER_X_TOKEN:
            return max(keys, key=lambda x: self.Q[state][x])

        min(keys, key=lambda x: self.Q[state][x])

    def _random_move(self, board):
        if random.random() < self.eps:
            try:
                locations = board.get_playable_locations()
                loc_len = len(locations)
                idx = np.random.randint(0, loc_len)
                loc = locations[idx]
                return (POSITIONS_TO_TOKEN[loc], loc)
            except Exception:
                breakpoint()

        action = self.get_best_action(str(board.get_board()))

        if action is None:
            locations = board.get_playable_locations()
            loc_len = len(locations)
            idx = np.random.randint(0, loc_len)
            loc = locations[idx]
            return (POSITIONS_TO_TOKEN[loc], loc)

        return (POSITIONS_TO_TOKEN[action], action)

    def _learn_one_game(self):
        board = Board()

        while board.state() == GameState.NOT_ENDED:
            current_state = str(board.get_board())
            action = self.get_best_action(current_state)

            if not action:
                position_token, action = self._random_move(board)
            else:
                position_token = POSITIONS_TO_TOKEN[action]

            board.play_position(position_token, PLAYER_X_TOKEN)
            board_state = board.state()
            board_next_state = str(board.get_board())

            if board_state == GameState.X_WON:
                self._update_q_learn(
                    current_state, board_next_state, 100, action)
                break

            if board_state == GameState.O_WON or board_state == GameState.DRAW:
                self._update_q_learn(
                    current_state, board_next_state, -100, action)
                break

            # Player O Turn
            position_token, _ = self._random_move(board)
            board.play_position(position_token, PLAYER_O_TOKEN)
            board_state = board.state()
            board_next_state = str(board.get_board())

            if board_state == GameState.O_WON or board_state == GameState.DRAW:
                self._update_q_learn(
                    current_state, board_next_state, -100, action)
                break

            if board_state == GameState.X_WON:
                self._update_q_learn(
                    current_state, board_next_state, 100, action)
                break

            self._update_q_learn(
                current_state, board_next_state, 0, action)

    def _update_q_learn(self, board_state: str, next_state: str, score: int, action):
        if board_state not in self.Q:
            self.Q[board_state] = {}

        if next_state not in self.Q:
            self.Q[next_state] = {}

        # Get the max next q value
        v = list(self.Q[next_state].values())
        max_next_q = max(v) if v else -2

        # Get current q value
        current_q = self.Q[board_state].get(action, -2)

        TD = score + self.gamma * max_next_q - current_q
        self.Q[board_state][action] = current_q + self.alpha * TD

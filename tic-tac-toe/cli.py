# /usr/bin/env python

from game import Game
from player import RandomAI, Human, MinMaxAI, QLearningAI
from constants import (
    PLAYER_X_TOKEN,
    PLAYER_O_TOKEN,
    GameState,
)

game_iterations = 1
verbose_output = True
player_x = Human(token=PLAYER_X_TOKEN)
player_o = RandomAI(token=PLAYER_O_TOKEN)

pick_player_x_msg = """
Pick Player X (Default: 1)

(1) Human
(2) Random AI
(3) Min Max AI
(4) Q-Learning AI

$ """

pick_player_o_msg = """
Pick Player O (Default: 2)

(1) Human
(2) Random AI
(3) Min Max AI
(4) Q-Learning AI

$ """

pick_iterations_msg = """
How many times do you want to play? (Default: 1)

$ """

pick_verbose_msg = """
Display board? (Verbose output Default: 1)

(1) True
(2) False

$ """

print("Player X always goes first!")

player_x_select = input(pick_player_x_msg)

if player_x_select != "":
    player_x_select = int(player_x_select)
    if player_x_select == 2:
        player_x = RandomAI(token=PLAYER_X_TOKEN)
    elif player_x_select == 3:
        player_x = MinMaxAI(token=PLAYER_X_TOKEN)
    elif player_x_select == 4:
        player_x = QLearningAI(token=PLAYER_X_TOKEN)
    elif player_x_select != 1:
        raise RuntimeError(
            f"Unknown selection for player X: {player_x_select}")

player_o_select = input(pick_player_o_msg)

if player_o_select != "":
    player_o_select = int(player_o_select)

    if player_o_select == 1:
        player_o = Human(token=PLAYER_O_TOKEN)
    elif player_o_select == 3:
        player_o = MinMaxAI(token=PLAYER_O_TOKEN)
    elif player_o_select == 4:
        player_o = QLearningAI(token=PLAYER_O_TOKEN)
    elif player_o_select != 2:
        raise RuntimeError(
            f"Unknown selection for player O: {player_o_select}")

game_iteration_select = input(pick_iterations_msg)

if game_iteration_select != "":
    game_iterations = int(game_iteration_select)

verbose_selection = input(pick_verbose_msg)

if verbose_selection != "":
    verbose_selection = int(verbose_selection)
    if verbose_selection == 2:
        verbose_output = False
    elif verbose_selection != 1:
        raise RuntimeError(f"Unknown verbose selection: {verbose_selection}")

game_results = {}

for i in range(0, game_iterations):
    game = Game(player_x=player_x, player_o=player_o, verbose=verbose_output)
    game.play()
    state = game.board.state()
    breakpoint()
    if state not in game_results.keys():
        game_results[state] = 1
    else:
        game_results[state] += 1

print(f"X ({player_x.__class__.__name__}) Wins: {game_results.get(GameState.X_WON, 0)}")
print(f"O ({player_o.__class__.__name__}) Wins: {game_results.get(GameState.O_WON, 0)}")
print(f"DRAWS: {game_results.get(GameState.DRAW, 0)}")

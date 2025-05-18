package main

import (
	"cart/utils"
	"cart/w4"
	"image"
)

type Game struct {
	board           [3][3]int
	currentPlayer   int
	cursor          image.Point
	frameCount      int
	animFrame       int
	winner          int
	seed            int64
	totalFrameCount int64
	rnd             func(uint) uint
	stars           []Star
	playerSprite    interface {
		Draw(image.Point, bool)
	}
}

func (g *Game) Move(X, Y int) {
	g.board[X][Y] = g.currentPlayer
	g.currentPlayer = g.currentPlayer%2 + 1
	var pos [3]image.Point
	g.winner, pos = g.CheckStatus()
	if g.winner == 1 || g.winner == 2 {
		g.board[pos[0].X][pos[0].Y] += 2
		g.board[pos[1].X][pos[1].Y] += 2
		g.board[pos[2].X][pos[2].Y] += 2
	}
}

func (g *Game) Update() {
	g.totalFrameCount++

	if g.frameCount%2 == 0 && len(g.stars) > 0 {
		for index := range g.stars {
			g.stars[index].X = g.stars[index].X + g.stars[index].VelX
			if g.stars[index].X > 160 {
				g.stars[index] = Star{
					X:    int(0 - g.rnd(40)),
					Y:    int(g.rnd(160)),
					VelX: int(g.rnd(4) + 1),
				}
			}
		}
	}

	switch g.winner {
	case 0:
		{
			button := utils.JustPressedGamepad(0)
			if button != 0 && len(g.stars) < 1 {
				g.rnd = Random(uint(g.totalFrameCount))
				g.stars = make([]Star, g.rnd(160)+160)
				for index := range g.stars {
					g.stars[index] = Star{
						X:    int(g.rnd(160)),
						Y:    int(g.rnd(160)),
						VelX: int(g.rnd(4) + 1),
					}
				}
			}

			switch button {
			case w4.BUTTON_LEFT:
				g.cursor.X--
				if g.cursor.X < 0 {
					g.cursor.X = 2
				}

			case w4.BUTTON_RIGHT:
				g.cursor.X = (g.cursor.X + 1) % 3

			case w4.BUTTON_UP:
				g.cursor.Y--
				if g.cursor.Y < 0 {
					g.cursor.Y = 2
				}

			case w4.BUTTON_DOWN:
				g.cursor.Y = (g.cursor.Y + 1) % 3

			case w4.BUTTON_1:
				if g.board[g.cursor.X][g.cursor.Y] == 0 {
					g.Move(g.cursor.X, g.cursor.Y)
				}
			case w4.BUTTON_2:
				X, Y := g.CPU()
				g.cursor = image.Pt(X, Y)
				g.Move(X, Y)
			}
		}

	default:
		if utils.JustPressedGamepad(0) != 0 {
			g.board = [3][3]int{
				{0, 0, 0},
				{0, 0, 0},
				{0, 0, 0},
			}
			g.currentPlayer = g.winner%2 + 1
			g.winner = 0
		}
	}
}

func (g *Game) Draw() {
	for _, star := range g.stars {
		*w4.DRAW_COLORS = 4 - uint16(star.VelX)
		w4.Line(star.X, star.Y, star.X, star.Y)
	}

	*w4.DRAW_COLORS = 0x4320

	board.Draw()

	g.frameCount = (g.frameCount + 1) % 30
	if g.frameCount == 0 {
		g.animFrame = (g.animFrame + 1) % 2
	}

	for x := range g.board {
		for y, playerID := range g.board[x] {
			win := false
			if playerID > 2 {
				playerID = playerID - 2
				win = true
			}
			if playerID != 0 {
				playerSprite[playerID-1].Draw(image.Point{X: x, Y: y}, win)
			}
		}
	}

	letters["W"].Draw(4, 18)
	letters["A"].Draw(6, 18)
	letters["S"].Draw(8, 18)
	letters["M"].Draw(10, 18)
	letters["-"].Draw(12, 19)
	letters["4"].Draw(14, 18)

	if g.winner == 1 || g.winner == 2 {
		nextSprite[g.winner-1].Draw()
		letters["W"].Draw(8, 0)
		letters["I"].Draw(10, 0)
		letters["N"].Draw(11, 0)
		letters["S"].Draw(13, 0)
	} else if g.winner == 0 {
		playerSprite[g.currentPlayer-1].Draw(g.cursor, g.animFrame == 0)
	} else {
		letters["D"].Draw(6, 0)
		letters["R"].Draw(8, 0)
		letters["A"].Draw(10, 0)
		letters["W"].Draw(12, 0)
	}
}

func (g *Game) CheckStatus() (playerID int, pos [3]image.Point) {
	for y := 0; y < 3; y++ {
		if id := g.board[0][y]; id != 0 && id == g.board[1][y] && id == g.board[2][y] {
			pos[0] = image.Pt(0, y)
			pos[1] = image.Pt(1, y)
			pos[2] = image.Pt(2, y)
			return id, pos
		}
	}

	for x := 0; x < 3; x++ {
		if id := g.board[x][0]; id != 0 && id == g.board[x][1] && id == g.board[x][2] {
			pos[0] = image.Pt(x, 0)
			pos[1] = image.Pt(x, 1)
			pos[2] = image.Pt(x, 2)
			return id, pos
		}
	}

	if id := g.board[0][0]; id != 0 && id == g.board[1][1] && id == g.board[2][2] {
		pos[0] = image.Pt(0, 0)
		pos[1] = image.Pt(1, 1)
		pos[2] = image.Pt(2, 2)
		return id, pos
	}

	if id := g.board[2][0]; id != 0 && id == g.board[1][1] && id == g.board[0][2] {
		pos[0] = image.Pt(2, 0)
		pos[1] = image.Pt(1, 1)
		pos[2] = image.Pt(0, 2)
		return id, pos
	}

	for x := 0; x < 3; x++ {
		for y := 0; y < 3; y++ {
			if g.board[x][y] == 0 {
				return 0, pos
			}
		}
	}

	return 3, pos
}

func (g *Game) CPU() (int, int) {
	nextPlayer := g.currentPlayer%2 + 1

	// Check if the current player can win
	for X := 0; X < 3; X++ {
		for Y := 0; Y < 3; Y++ {
			if g.board[X][Y] == 0 {
				g.board[X][Y] = g.currentPlayer
				if id, _ := g.CheckStatus(); id == g.currentPlayer {
					g.board[X][Y] = 0
					return X, Y
				}
				g.board[X][Y] = 0
			}
		}
	}

	// Check if the current player can avoid a loss
	for X := 0; X < 3; X++ {
		for Y := 0; Y < 3; Y++ {
			if g.board[X][Y] == 0 {
				g.board[X][Y] = nextPlayer
				if id, _ := g.CheckStatus(); id == nextPlayer {
					g.board[X][Y] = 0
					return X, Y
				}
				g.board[X][Y] = 0
			}
		}
	}

	// Pick a random field
	fields := make([]image.Point, 0)
	for X := 0; X < 3; X++ {
		for Y := 0; Y < 3; Y++ {
			if g.board[X][Y] == 0 {
				fields = append(fields, image.Point{X: X, Y: Y})
			}
		}
	}
	l := len(fields)
	index := int(g.totalFrameCount) % l
	return fields[index].X, fields[index].Y
}

var game = &Game{
	currentPlayer: 1,
}

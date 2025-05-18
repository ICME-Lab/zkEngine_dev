package main

import (
	"cart/w4"
	"image"
)

type Tile struct {
	ID  int
	Pos image.Point
}

type Player struct {
	TilesNormal []Tile
	TilesWin    []Tile
}

type Next []Tile

func (p *Player) Draw(pos image.Point, win bool) {
	ts := p.TilesNormal
	if win {
		ts = p.TilesWin
	}
	for _, tile := range ts {
		x := tile.Pos.X*8 + (pos.X*6+2)*8
		y := tile.Pos.Y*8 + (pos.Y*6+2)*8
		sx := uint(tile.ID%12) * 8
		sy := uint(tile.ID/12) * 8
		w4.BlitSub(&tileset.Data[0], x, y, 8, 8, sx, sy, tileset.Width, tileset.Flags)
	}

}

func (n Next) Draw() {
	for _, tile := range n {
		x := tile.Pos.X*8 + 5*8
		y := tile.Pos.Y * 8
		sx := uint(tile.ID%12) * 8
		sy := uint(tile.ID/12) * 8
		w4.BlitSub(&tileset.Data[0], x, y, 8, 8, sx, sy, tileset.Width, tileset.Flags)
	}
}

var playerSprite = []Player{
	{
		TilesNormal: []Tile{
			{ID: 6*12 + 0, Pos: image.Point{X: 0, Y: 0}},
			{ID: 6*12 + 1, Pos: image.Point{X: 3, Y: 0}},
			{ID: 2*12 + 2, Pos: image.Point{X: 1, Y: 1}},
			{ID: 3*12 + 2, Pos: image.Point{X: 2, Y: 1}},
			{ID: 2*12 + 2, Pos: image.Point{X: 2, Y: 2}},
			{ID: 3*12 + 2, Pos: image.Point{X: 1, Y: 2}},
			{ID: 6*12 + 2, Pos: image.Point{X: 0, Y: 3}},
			{ID: 6*12 + 3, Pos: image.Point{X: 3, Y: 3}},

			{ID: 8*12 + 1, Pos: image.Point{X: 0, Y: 2}},
			{ID: 9*12 + 1, Pos: image.Point{X: 0, Y: 1}},
			{ID: 8*12 + 2, Pos: image.Point{X: 1, Y: 0}},
			{ID: 9*12 + 2, Pos: image.Point{X: 1, Y: 3}},

			{ID: 8*12 + 1, Pos: image.Point{X: 2, Y: 0}},
			{ID: 9*12 + 1, Pos: image.Point{X: 2, Y: 3}},
			{ID: 8*12 + 2, Pos: image.Point{X: 3, Y: 2}},
			{ID: 9*12 + 2, Pos: image.Point{X: 3, Y: 1}},
		},
		TilesWin: []Tile{
			{ID: 6*12 + 6, Pos: image.Point{X: 0, Y: 0}},
			{ID: 6*12 + 7, Pos: image.Point{X: 3, Y: 0}},
			{ID: 3*12 + 3, Pos: image.Point{X: 1, Y: 1}},
			{ID: 2*12 + 3, Pos: image.Point{X: 2, Y: 1}},
			{ID: 3*12 + 3, Pos: image.Point{X: 2, Y: 2}},
			{ID: 2*12 + 3, Pos: image.Point{X: 1, Y: 2}},
			{ID: 6*12 + 8, Pos: image.Point{X: 0, Y: 3}},
			{ID: 6*12 + 9, Pos: image.Point{X: 3, Y: 3}},

			{ID: 8*12 + 7, Pos: image.Point{X: 0, Y: 2}},
			{ID: 9*12 + 7, Pos: image.Point{X: 0, Y: 1}},
			{ID: 8*12 + 8, Pos: image.Point{X: 1, Y: 0}},
			{ID: 9*12 + 8, Pos: image.Point{X: 1, Y: 3}},

			{ID: 8*12 + 7, Pos: image.Point{X: 2, Y: 0}},
			{ID: 9*12 + 7, Pos: image.Point{X: 2, Y: 3}},
			{ID: 8*12 + 8, Pos: image.Point{X: 3, Y: 2}},
			{ID: 9*12 + 8, Pos: image.Point{X: 3, Y: 1}},
		},
	},
	{
		TilesNormal: []Tile{
			{ID: 7*12 + 0, Pos: image.Point{X: 0, Y: 0}},
			{ID: 7*12 + 1, Pos: image.Point{X: 1, Y: 0}},
			{ID: 7*12 + 2, Pos: image.Point{X: 2, Y: 0}},
			{ID: 7*12 + 3, Pos: image.Point{X: 3, Y: 0}},
			{ID: 8*12 + 0, Pos: image.Point{X: 0, Y: 1}},
			{ID: 8*12 + 3, Pos: image.Point{X: 3, Y: 1}},
			{ID: 9*12 + 0, Pos: image.Point{X: 0, Y: 2}},
			{ID: 9*12 + 3, Pos: image.Point{X: 3, Y: 2}},
			{ID: 10*12 + 0, Pos: image.Point{X: 0, Y: 3}},
			{ID: 10*12 + 1, Pos: image.Point{X: 1, Y: 3}},
			{ID: 10*12 + 2, Pos: image.Point{X: 2, Y: 3}},
			{ID: 10*12 + 3, Pos: image.Point{X: 3, Y: 3}},
		},
		TilesWin: []Tile{
			{ID: 7*12 + 6, Pos: image.Point{X: 0, Y: 0}},
			{ID: 7*12 + 7, Pos: image.Point{X: 1, Y: 0}},
			{ID: 7*12 + 8, Pos: image.Point{X: 2, Y: 0}},
			{ID: 7*12 + 9, Pos: image.Point{X: 3, Y: 0}},
			{ID: 8*12 + 6, Pos: image.Point{X: 0, Y: 1}},
			{ID: 8*12 + 9, Pos: image.Point{X: 3, Y: 1}},
			{ID: 9*12 + 6, Pos: image.Point{X: 0, Y: 2}},
			{ID: 9*12 + 9, Pos: image.Point{X: 3, Y: 2}},
			{ID: 10*12 + 6, Pos: image.Point{X: 0, Y: 3}},
			{ID: 10*12 + 7, Pos: image.Point{X: 1, Y: 3}},
			{ID: 10*12 + 8, Pos: image.Point{X: 2, Y: 3}},
			{ID: 10*12 + 9, Pos: image.Point{X: 3, Y: 3}},
		},
	},
}

var nextSprite = []Next{
	[]Tile{
		{ID: 0*12 + 0, Pos: image.Point{X: 0, Y: 0}},
		{ID: 0*12 + 1, Pos: image.Point{X: 1, Y: 0}},
		{ID: 1*12 + 0, Pos: image.Point{X: 0, Y: 1}},
		{ID: 1*12 + 1, Pos: image.Point{X: 1, Y: 1}},
	},
	[]Tile{
		{ID: 2*12 + 0, Pos: image.Point{X: 0, Y: 0}},
		{ID: 2*12 + 1, Pos: image.Point{X: 1, Y: 0}},
		{ID: 3*12 + 0, Pos: image.Point{X: 0, Y: 1}},
		{ID: 3*12 + 1, Pos: image.Point{X: 1, Y: 1}},
	},
}

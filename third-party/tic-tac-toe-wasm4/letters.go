package main

import (
	"cart/w4"
	"image"
)

type Letter []Tile

var letters = map[string]Letter{
	"A": {
		{
			ID: 2*12 + 6, Pos: image.Pt(0, 0),
		},
		{
			ID: 2*12 + 7, Pos: image.Pt(1, 0),
		},
		{
			ID: 3*12 + 6, Pos: image.Pt(0, 1),
		},
		{
			ID: 3*12 + 7, Pos: image.Pt(1, 1),
		},
	},
	"D": {
		{
			ID: 0*12 + 10, Pos: image.Pt(0, 0),
		},
		{
			ID: 0*12 + 11, Pos: image.Pt(1, 0),
		},
		{
			ID: 1*12 + 10, Pos: image.Pt(0, 1),
		},
		{
			ID: 1*12 + 11, Pos: image.Pt(1, 1),
		},
	},
	"E": {
		{
			ID: 2*12 + 6, Pos: image.Pt(0, 0),
		},
		{
			ID: 2*12 + 7, Pos: image.Pt(0, 1),
		},
		{
			ID: 3*12 + 6, Pos: image.Pt(1, 0),
		},
		{
			ID: 3*12 + 7, Pos: image.Pt(1, 1),
		},
	},
	"I": {
		{
			ID: 5*12 + 11, Pos: image.Pt(0, 0),
		},
		{
			ID: 6*12 + 11, Pos: image.Pt(0, 1),
		},
	},
	"M": {
		{
			ID: 0*12 + 6, Pos: image.Pt(0, 0),
		},
		{
			ID: 1*12 + 6, Pos: image.Pt(0, 1),
		},
		{
			ID: 7*12 + 11, Pos: image.Pt(1, 0),
		},
		{
			ID: 8*12 + 11, Pos: image.Pt(1, 1),
		},
	},
	"N": {
		{
			ID: 0*12 + 6, Pos: image.Pt(0, 0),
		},
		{
			ID: 0*12 + 7, Pos: image.Pt(1, 0),
		},
		{
			ID: 1*12 + 6, Pos: image.Pt(0, 1),
		},
		{
			ID: 1*12 + 7, Pos: image.Pt(1, 1),
		},
	},
	"R": {
		{
			ID: 2*12 + 10, Pos: image.Pt(0, 0),
		},
		{
			ID: 2*12 + 11, Pos: image.Pt(1, 0),
		},
		{
			ID: 3*12 + 10, Pos: image.Pt(0, 1),
		},
		{
			ID: 3*12 + 11, Pos: image.Pt(1, 1),
		},
	},
	"S": {
		{
			ID: 2*12 + 8, Pos: image.Pt(0, 0),
		},
		{
			ID: 2*12 + 9, Pos: image.Pt(1, 0),
		},
		{
			ID: 3*12 + 8, Pos: image.Pt(0, 1),
		},
		{
			ID: 3*12 + 9, Pos: image.Pt(1, 1),
		},
	},
	"W": {
		{
			ID: 7*12 + 10, Pos: image.Pt(0, 0),
		},
		{
			ID: 8*12 + 10, Pos: image.Pt(0, 1),
		},
		{
			ID: 0*12 + 7, Pos: image.Pt(1, 0),
		},
		{
			ID: 1*12 + 7, Pos: image.Pt(1, 1),
		},
	},
	"-": {
		{
			ID: 1*12 + 2, Pos: image.Pt(0, 0),
		},
	},
	"4": {
		{
			ID: 9*12 + 10, Pos: image.Pt(0, 0),
		},
		{
			ID: 9*12 + 11, Pos: image.Pt(1, 0),
		},
		{
			ID: 10*12 + 10, Pos: image.Pt(0, 1),
		},
		{
			ID: 10*12 + 11, Pos: image.Pt(1, 1),
		},
	},
}

func (l Letter) Draw(X, Y int) {
	for _, tile := range l {
		x := tile.Pos.X*8 + X*8
		y := tile.Pos.Y*8 + Y*8
		sx := uint(tile.ID%12) * 8
		sy := uint(tile.ID/12) * 8
		w4.BlitSub(&tileset.Data[0], x, y, 8, 8, sx, sy, tileset.Width, tileset.Flags)
	}
}

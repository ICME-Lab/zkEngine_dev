package main

//go:export update
func update() {
	game.Update()
	game.Draw()
}

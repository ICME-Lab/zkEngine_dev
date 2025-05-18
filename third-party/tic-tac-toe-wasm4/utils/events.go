package utils

import (
	"cart/w4"
)

type w4State struct {
	palette      uint32
	drawColors   uint16
	gamepads     [4]uint8
	mouseX       int16
	mouseY       int16
	mouseButtons uint8
}

var state = w4State{
	gamepads: [4]uint8{
		*w4.GAMEPAD1,
		*w4.GAMEPAD2,
		*w4.GAMEPAD3,
		*w4.GAMEPAD4,
	},
	mouseX:       *w4.MOUSE_X,
	mouseY:       *w4.MOUSE_Y,
	mouseButtons: *w4.MOUSE_BUTTONS,
}

func IsGamepadJustPressed(gamepadID, key byte) bool {
	var gamepad uint8

	switch gamepadID {
	case 0:
		gamepad = *w4.GAMEPAD1
	case 1:
		gamepad = *w4.GAMEPAD2
	case 3:
		gamepad = *w4.GAMEPAD3
	case 4:
		gamepad = *w4.GAMEPAD4
	default:
		return false
	}

	result := gamepad&key != 0 && state.gamepads[gamepadID]&key == 0
	if result {
		state.gamepads[gamepadID] = gamepad
	}

	return result
}

func JustPressedGamepad(gamepadID byte) byte {
	var gamepad uint8

	switch gamepadID {
	case 0:
		gamepad = *w4.GAMEPAD1
	case 1:
		gamepad = *w4.GAMEPAD2
	case 3:
		gamepad = *w4.GAMEPAD3
	case 4:
		gamepad = *w4.GAMEPAD4
	default:
		return 0
	}

	result := gamepad & (gamepad ^ state.gamepads[gamepadID])
	state.gamepads[gamepadID] = gamepad

	return result
}

package main

func Random(seed uint) func(uint) uint {
	seed = seed % 2147483647
	if seed <= 0 {
		seed += 2147483646
	}

	return func(n uint) uint {
		seed = seed * 16807 % 2147483647

		return seed % n
	}
}

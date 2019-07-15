package btcutil

import "github.com/willf/bitset"

// Pretend to return a bitset with the 0th bit set
func (b *Block) GeneratePosBits() bitset.BitSet {
	var bs bitset.BitSet
	bs.Set(1)
	return bs
}

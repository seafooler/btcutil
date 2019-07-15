package btcutil

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/deckarep/golang-set"
	"github.com/willf/bitset"
	"io"
	"sort"
)

type BlockBranch struct {
	Header wire.BlockHeader
	Transactions []*wire.MsgTx
	PosBits bitset.BitSet
	MerkleHashes []*chainhash.Hash
}

func (b *Block) BuildBlockBranch(posBits bitset.BitSet) BlockBranch {
	msgBlock := b.msgBlock
	lenTxs := len(msgBlock.Transactions)
	nextPoT := nextPowerOfTwo(lenTxs)
	merkleBranch := BlockBranch{
		Header: b.msgBlock.Header,
		PosBits: posBits,
		Transactions: make([]*wire.MsgTx, posBits.Count()),
	}
	txPos := 0
	posInts := make([]int, posBits.Count())
	for i, e := posBits.NextSet(0); e; i, e = posBits.NextSet(i + 1) {
		//fmt.Println("The following bit is set:", i, e)
		merkleBranch.Transactions[txPos] = msgBlock.Transactions[i]
		posInts[txPos] = int(i)
		txPos ++
	}

	txs := b.Transactions()
	merkles := BuildMerkleTreeStore(txs, false)

	// select the hash positions
	// if there are 16 transactions whose positions from 0 to 15,
	// and the transactions of interest are the 4th and 9th
	// the hash positions to store include [18, 19, 20, 21, 24, 25, 26, 27, 28, 29, 30]
	posMerklesToStore := mapset.NewSet()
	for _, p := range posInts {
		for i:=1; i<nextPoT; i=i*2 {
			hashPos := 2*nextPoT - nextPoT/i + p/2/i
			if hashPos%2 == 0 {
				posMerklesToStore.Add(hashPos)
				posMerklesToStore.Add(hashPos+1)
			} else {
				posMerklesToStore.Add(hashPos)
				posMerklesToStore.Add(hashPos-1)
			}
		}
		if p % 2 == 0 {
			posMerklesToStore.Add(p+1)
		} else {
			posMerklesToStore.Add(p-1)
		}
	}
	posMerklesToStore.Remove(2*nextPoT-1)
	posMerklesToStoreSlice := posMerklesToStore.ToSlice()
	merkleBranch.MerkleHashes = make([]*chainhash.Hash, len(posMerklesToStoreSlice))
	pMTSS := make([]int, len(posMerklesToStoreSlice))
	for i, p := range(posMerklesToStoreSlice) {
		pMTSS[i] = p.(int)
	}
	sort.Ints(pMTSS)

	for i,p := range(pMTSS) {
		merkleBranch.MerkleHashes[i] = merkles[p]
	}
	return merkleBranch
}

type JidarBlock struct {
	BlockBranch *BlockBranch
	serializedBlock []byte
	BlockHash *chainhash.Hash
	blockHeight int32
	transactions []*Tx
}

func MakeJidarBlock(b *Block, posBits bitset.BitSet) *JidarBlock {
	m := b.BuildBlockBranch(posBits)
	return &JidarBlock{
		BlockBranch: &m,
		BlockHash: b.blockHash,
		blockHeight: b.blockHeight,
		transactions: b.Transactions(),
	}
}

func (bb * BlockBranch) BtcEncode(w io.Writer, pver uint32, enc wire.MessageEncoding) error {
	// write header
	err := wire.WriteBlockHeader(w, pver, &bb.Header)
	if err != nil {
		return err
	}

	// write transactions
	err = wire.WriteVarInt(w, pver, uint64(len(bb.Transactions)))
	if err != nil {
		return err
	}
	for _, tx := range bb.Transactions {
		err = tx.BtcEncode(w, pver, enc)
		if err != nil {
			return err
		}
	}

	// write PosBits
	bi, err := bb.PosBits.MarshalBinary()
	if err != nil {
		return err
	}
	err = wire.WriteVarBytes(w, pver, bi)
	if err != nil {
		return err
	}

	// write MerkleHashes
	var numMerkleHashes uint64 = uint64(len(bb.MerkleHashes))
	wire.WriteVarInt(w, pver, numMerkleHashes)
	for _, h := range bb.MerkleHashes {
		var hbytes [chainhash.HashSize]byte
		if h == nil {
			copy(hbytes[:], "nil")
		} else {
			hbytes = [chainhash.HashSize]byte(*h)
		}
		w.Write(hbytes[:])
	}

	return nil
}

func (bb * BlockBranch) BtcDecode(r io.Reader, pver uint32, enc wire.MessageEncoding) error {
	// read header
	err := wire.ReadBlockHeader(r, pver, &bb.Header)
	if err != nil {
		return err
	}

	txCount, err := wire.ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// read transactions
	if txCount > wire.MaxTxPerBlock {
		str := fmt.Sprintf("too many transactions to fit into a block "+
			"[count %d, max %d]", txCount, wire.MaxTxPerBlock)
		return &wire.MessageError{"MsgBlock.BtcDecode", str}
	}

	bb.Transactions = make([]*wire.MsgTx, 0, txCount)
	for i := uint64(0); i < txCount; i++ {
		tx := wire.MsgTx{}
		err := tx.BtcDecode(r, pver, enc)
		if err != nil {
			return err
		}
		bb.Transactions = append(bb.Transactions, &tx)
	}

	// read PosBits
	bi, err := wire.ReadVarBytes(r, pver, 1000, "Binary of PosBits")
	if err != nil {
		return err
	}
	var posBits bitset.BitSet
	err = posBits.UnmarshalBinary(bi)
	if err != nil {
		return nil
	}
	bb.PosBits = posBits

	// read MerkleHashes
	hashCount, err := wire.ReadVarInt(r, pver)
	if err != nil {
		return nil
	}
	if bb.MerkleHashes == nil {
		bb.MerkleHashes = make([]*chainhash.Hash, hashCount)
	}
	for i:= 0; i< int(hashCount); i++ {
		buf := make([]byte, chainhash.HashSize)
		io.ReadFull(r, buf)
		var tmpBytes [chainhash.HashSize]byte
		copy(tmpBytes[:], buf[:chainhash.HashSize])
		if bb.MerkleHashes[i] == nil {
			bb.MerkleHashes[i] = new(chainhash.Hash)
		}
		*bb.MerkleHashes[i] = chainhash.Hash(tmpBytes)
	}

	return nil
}

func (bb * BlockBranch) SerializeSizeStripped() int {
	// Header size
	n := wire.BlockHeaderLen

	// Txs size
	n += wire.VarIntSerializeSize(uint64(len(bb.Transactions)))
	for _, tx := range bb.Transactions {
		n += tx.SerializeSizeStripped()
	}

	// PosBits size
	bi, err := bb.PosBits.MarshalBinary()
	if err != nil {
		return -1
	}
	n += wire.VarIntSerializeSize(uint64(len(bi)))
	n += len(bi)

	// MerkleHashes size
	n += wire.VarIntSerializeSize(uint64(len(bb.MerkleHashes)))
	n += chainhash.HashSize * len(bb.MerkleHashes)

	return n
}

func (bb * BlockBranch) SerializeNoWitness (w io.Writer) error {
	return bb.BtcEncode(w, 0, wire.BaseEncoding)
}
func (b *JidarBlock) Bytes() ([]byte, error) {
	// Return the cached serialized bytes if it has already been generated.
	if len(b.serializedBlock) != 0 {
		return b.serializedBlock, nil
	}

	// Serialize the BlockBranch.
	w := bytes.NewBuffer(make([]byte, 0, b.BlockBranch.SerializeSizeStripped()))
	err := b.BlockBranch.SerializeNoWitness(w)
	if err != nil {
		return nil, err
	}
	serializedBlock := w.Bytes()

	// Cache the serialized bytes and return them.
	b.serializedBlock = serializedBlock
	return serializedBlock, nil
}
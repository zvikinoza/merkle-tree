package merkletree

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
)

// note: crypto/hash.Hash.Write never returns error.

// MerkleTree ...
type MerkleTree struct {
	root        *node
	data        []byte
	segmentSize uint32
	newHash     func() hash.Hash
}

type node struct {
	left  *node
	right *node
	hash  hash.Hash
}

func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// NewMerkleTree returns new merkle tree created by the data in the 'data'.
// All leaves will we 'segmentSize' bytes except the last leaf,
// which will not be padded out if there are not enough bytes remaining in the 'data'.
func NewMerkleTree(data []byte, segmentSize uint32) (*MerkleTree, error) {
	return NewMerkleTreeWithCostumHash(data, segmentSize, sha256.New)
}

// NewMerkleTreeWithCostumHash ...
func NewMerkleTreeWithCostumHash(data []byte, segmentSize uint32, hashfn func() hash.Hash) (*MerkleTree, error) {
	mt := MerkleTree{
		root:        nil,
		data:        data,
		segmentSize: segmentSize,
		newHash:     hashfn,
	}

	segments := chopData(data, segmentSize)
	mt.root = mt.buildTree(segments, uint32(0), uint32(len(data)))
	return &mt, nil
}

// chop data in segmentSize pieces
func chopData(data []byte, segmentSize uint32) [][]byte {
	segments := [][]byte{}
	dataLen := uint32(len(data))
	for i := uint32(0); i < dataLen; i += segmentSize {
		currSegmentSize := min(dataLen-i, segmentSize)
		segment := make([]byte, currSegmentSize)
		_ = copy(segment, data[i:i+currSegmentSize])
		segments = append(segments, segment)
	}
	return segments
}

// BuildTree ...
func (mt *MerkleTree) buildTree(segments [][]byte, start, end uint32) *node {
	// base case, no more segments left
	if len(segments) == 0 {
		return nil
	}

	// leaf node
	if end-start <= mt.segmentSize {
		leaf := &node{
			left:  nil,
			right: nil,
			hash:  mt.newHash(),
		}
		_, _ = leaf.hash.Write(segments[0])
		segments = segments[1:]
		return leaf
	}

	// intermediate node
	mid := start + ((end - start) / 2)
	n := &node{
		left:  mt.buildTree(segments, start, mid),
		right: mt.buildTree(segments, mid, end),
		hash:  mt.newHash(),
	}

	concat := append(n.left.hash.Sum(nil), n.right.hash.Sum(nil)...)
	_, _ = n.hash.Write(concat)

	return n
}

// GetRootHash ...
func (mt *MerkleTree) GetRootHash() []byte {
	return mt.root.hash.Sum(nil)
}

// Validate entire trees' correctness
func (mt *MerkleTree) Validate() (bool, error) {
	nmt, err := NewMerkleTreeWithCostumHash(mt.data, mt.segmentSize, mt.newHash)
	if err != nil {
		return false, nil
	}
	return mt.Equals(nmt), nil
}

func (mt *MerkleTree) String() string {
	str := fmt.Sprintf("MerkleTree:\ndata:%v\nsegmentSize:%v\ntree:\n", mt.data, mt.segmentSize)
	str += subTreeToString(mt.root, "")
	return str
}

// Equals ...
func (mt *MerkleTree) Equals(other *MerkleTree) bool {
	return mt.root.subTreeEquals(other.root)
}

func (n *node) subTreeEquals(o *node) bool {
	if n == nil && o == nil {
		return true
	}
	if o == nil || n == nil {
		return false
	}
	if !bytes.Equal(n.hash.Sum(nil), n.hash.Sum(nil)) {
		return false
	}

	return n.left.subTreeEquals(o.left) && n.right.subTreeEquals(o.right)
}

func subTreeToString(n *node, prepad string) string {
	if n == nil {
		return ""
	}
	return prepad + fmt.Sprintf("hash:%v", n.hash.Sum(nil)) +
		subTreeToString(n.left, prepad+"\t") +
		subTreeToString(n.right, prepad+"\t")
}

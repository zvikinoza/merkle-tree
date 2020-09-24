package merkletree

import (
	"crypto/sha256"
	"hash"
)

// Data to be added in merkle tree must
// have comarison and calculating hash functions
type Data interface {
	Equals(other Data) (bool, error)
	Hash() ([]byte, error)
}

// MerkleTree ...
type MerkleTree struct {
	root   *node
	data   []Data
	hashfn func() hash.Hash
}

type node struct {
	left  *node
	right *node
	hash  hash.Hash
}

// NewMerkleTree ...
func NewMerkleTree(d []Data) (*MerkleTree, error) {
	return NewCostumHasMerkleTree(d, sha256.New)
}

// NewCostumHasMerkleTree ...
func NewCostumHasMerkleTree(d []Data, hash func() hash.Hash) (*MerkleTree, error) {
	mt := MerkleTree{
		root:   nil,
		data:   d,
		hashfn: hash,
	}

	return &mt, nil
}

// GetRootHash ...
func (mt *MerkleTree) GetRootHash() []byte {
	return mt.root.hash.Sum(nil)
}

// Validate entire trees' correctness
func (mt *MerkleTree) Validate() (bool, error) {
	return false, nil
}

func (mt *MerkleTree) String() (string, error) {
	return "", nil
}

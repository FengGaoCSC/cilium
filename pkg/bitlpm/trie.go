// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bittrie

// Trie is a non-thread-safe binary trie that indexes arbitrarily long
// bit-based keys with associated prefixes (that is, "masks") indexed from
// [most significant bit] ("MSB") to [least significant bit] ("LSB") using
// the [longest prefix match algorithm].
//
// Each method's comments describes the mechanism of how the method
// works.
//
// [most significant bit]: https://en.wikipedia.org/wiki/Bit_numbering#Most_significant_bit
// [least significant bit]: https://en.wikipedia.org/wiki/Bit_numbering#Least_significant_bit
// [longest prefix match algorithm]: https://en.wikipedia.org/wiki/Longest_prefix_match
type Trie[K, T any] interface {
	// Update updates the trie with a a prefix, key, and value.
	//
	// Note:If prefix exceeds the Trie's maximum prefix, it will be set
	// to the Trie's maximum prefix.
	Update(prefix uint, key K, value T)
	// Delete removes a key with the given prefix and returns
	// false if the key was not found.
	// Note: If prefix exceeds the Trie's maximum prefix, it will be set
	// to the Trie's maximum prefix.
	Delete(prefix uint, key K) bool
	// Lookup lookups any key that matches to at least
	// the prefix argument.
	// Note: If prefix exceeds the Trie's maximum prefix, it will be set
	// to the Trie's maximum prefix.
	Lookup(prefix uint, key K) T
	// Len returns the number of entries in the Trie
	Len() uint
	// ForEach iterates over every element of the Trie.
	ForEach(ForEachFunc[K, T])
}

// ForEachFunc is an interface for using the ForEach method of
// all Trie types.
type ForEachFunc[K, T any] func(prefix uint, key K, value T) bool

// Key is an interface that implements all the necessary
// methods to index and retrieve keys.
type Key[K any] interface {
	// Overlap returns the amount of bits that
	// are the same between this key and the argument
	// value, starting from MSB.
	Overlap(K) uint
	// BitValueAt returns the value of the bit at an argument
	// index. MSB is 0 and LSB is n.
	BitValueAt(uint) uint8
	// Value returns the underlying value of the Key.
	Value() K
}

// trie is the generic implementation of a bit-trie that can
// accept arbitrary keys conforming to the Key[K] interface.
type trie[K, T any] struct {
	root      *node[K, T]
	maxPrefix uint
	entries   uint
}

// NewTrie returns a Trie that accepts the Key[K any] interface
// as its key argument. This enables the user of this Trie to
// define their own bit-key.
func NewTrie[K any, T any](maxPrefix uint) Trie[Key[K], T] {
	return &trie[K, T]{
		maxPrefix: maxPrefix,
	}
}

// node represents a specific key and prefix in the trie
type node[K, T any] struct {
	children     [2]*node[K, T]
	prefixLen    uint
	key          Key[K]
	intermediate bool
	value        T
}

// Lookup returns the longest or most "specific" key that matches the key
// and prefix being looked up.
//
// Lookup starts traversal at the root key (or "node") in the trie.
// The key and prefix being looked-up (the "lookup" key and prefix) are
// compared to the a trie node's key and prefix (the "compare" key and
// prefix) to determine the extent to which the keys match (from MSB to
// LSB) up to the **least** specific (or lowest) prefix of the two keys
// (for example, if one of the keys has a prefix of 2 and the other has
// a prefix of 3 then the two keys will be compared up to the 2nd bit).
// If the key's match less than the compare prefix (that is, the lookup
// key did not fully match the compare key) then the previous compare
// key that matched is returned. If there was no previous key then there
// is no match. If the key's match was greater than the compare prefix
// then the compare key **could be** the most specific match on the trie,
// but traversal continues to ensure that there is not a more specific
// (that is, higher) match. The next bit, after the match length (between
// the pimary key and node key), on the primary key is looked up to
// determine which child of the current node to traverse to to
// check if there is a more specific match. If there is no child then
// the last match is returned. Otherwise traversal continues.
//
// Note: Lookup sets any prefixLen argument that exceeds the maximum
// prefix allowed by the trie to the maximum prefix allowed by the
// trie.
func (t *trie[K, T]) Lookup(prefixLen uint, k Key[K]) T {
	// default return value
	var d T
	if k == nil {
		return d
	}
	prefixLen = min(prefixLen, t.maxPrefix)

	var found *node[K, T]
	currentNode := t.root
	for currentNode != nil {
		matchLen := t.longestPrefixMatch(currentNode, prefixLen, k)
		// The keys match to the maximum prefix allowed by
		// the trie, return the current-node's value.
		if matchLen == t.maxPrefix {
			return currentNode.value
		}
		// The current-node is more specific than the lookup-{prefix,key}.
		// the last match is the return value (which might be nil/nothing).
		if matchLen < currentNode.prefixLen {
			break
		}
		// If the current-node is intermediate it cannot be a match,
		// but one of its childrend might be.
		if !currentNode.intermediate {
			found = currentNode
		}
		currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)]
	}
	if found == nil {
		return d
	}
	return found.value
}

// Update inserts or replaces a key and prefix (an "update" key and
// prefix) below keys that match it with a smaller (that is, less
// specific) prefix and above keys that match it with a
// more specific (that is "higher") prefix.
//
// Update start with the root key (or "node"). The update key and compare
// key are compared for the match length between them (see the
// `Lookup` comments for details on how this works). If the match
// length is exactly equal to the compare prefix then traversal
// continues as the next bit after the match length in the update key
// corresponds to one of the two child slots that belong to the compare
// key. If the match length is not exactly equal, or there is no child
// to traverse to, or the compare prefix is exactly equal to the
// update prefix (these conditions are not mutually exclusive) then traversal
// is finished. There are four possibile insertion/replacement condtions
// to consider:
//  1. The compare key is nil (that is, an empty "slot"), in which
//     case the previous key iterated over should be the upate-key's
//     parent. If there is not parent then the compare key is now the
//     root key (or "node").
//  2. The compare key matches the update-node to the exact
//     prefix. Then the update key should replace the compare key.
//  3. The compare key matches the update key to the upate prefix,
//     but compare prefix is greater than the update prefix. The
//     compare key should become a child of the update key.
//  4. The compare key does not match with the update key to either
//     the compare prefix or the update prefix. An intermediate node
//     needs to be inserted that replaces the current position of the
//     compare key, but give it a prefix of the match between the
//     update key and compare key. The compare key and update key
//     become siblings.
//
// Intermediate keys/nodes:
// Sometimes when a new key is inserted it does not match any key up to
// its own prefix or its closest matching key's prefix. When this
// happens an intermediate key is inserted that has the closest matching
// key's prefix with a new prefix that equals the match between the update
// key and closest match key. The new intermediate key replaces the closest
// match key's position in the trie and takes the closest match key and
// update key as children.
//
// For example, assuming a key size of 8 bytes, adding the prefix-keys of
// "0b001/8"(1-1), "0b010/7"(2-3), and "0b100/6"(4-7) would follow this logic:
//
//  1. "0b001/8" gets added as the first key. It becomes the root key.
//  2. "0b010/7" is added. It will match "0b001/8" (the root key) up to
//     6 bits, because "0b010/7"'s 7th bit (which is prefixed/protected)
//     is 1  and "0b001/8" has a prefixed/protected 7th bit of 0.
//     In this case, an intermediate key will be created with a key of
//     0b001 and a prefix of 6 (the extent to which "0b010/7"
//     and "0b001/8" match). The new intermediate key, "0b001/6", will have
//     children "0b001/8" (in the 0 slot) and "0b010/7" (in the 1 slot).
//     This new intermediate key become the new root key.
//  3. When "0b100/6" is added it will match the new root (which happens to
//     be an intermediate key) "0b001/6" up to 5 bits. Therefore another
//     intermediate key of "0b001/5" will be created, becoming the new root
//     key. "0b001/6" will become the new intermediate key's child in the
//     0 slot and "0b100/6" will be in the 1 slot. "0b001/5" becomes the
//     new root key.
//
// Note: Update sets any prefixLen argument that exceeds the maximum
// prefix allowed by the trie to the maximum prefix allowed by the
// trie.
func (t *trie[K, T]) Update(prefixLen uint, k Key[K], value T) {
	if k == nil {
		return
	}
	prefixLen = min(prefixLen, t.maxPrefix)
	updateNode := &node[K, T]{
		prefixLen: prefixLen,
		key:       k,
		value:     value,
	}

	var (
		matchLen uint
		parent   *node[K, T]
		bitVal   uint8
	)

	currentNode := t.root
	for currentNode != nil {
		matchLen = t.longestPrefixMatch(currentNode, prefixLen, k)
		// The current node does not match the update-{prefix,key}
		// or the current node matches to the maximum extent
		// allowable by either the trie or the update-prefix.
		if currentNode.prefixLen != matchLen ||
			currentNode.prefixLen == t.maxPrefix ||
			currentNode.prefixLen == prefixLen {
			break
		}
		bitVal = k.BitValueAt(currentNode.prefixLen)
		parent = currentNode
		currentNode = currentNode.children[bitVal]
	}
	t.entries++
	// Empty slot.
	if currentNode == nil {
		if parent == nil {
			t.root = updateNode
		} else {
			parent.children[bitVal] = updateNode
		}
		return
	}
	// There are three cases:
	// 1. The current-node matches the update-node to the exact
	//    prefix. Then the update-node should replace the current-node.
	// 2. The current-node matches the update-node, but the
	//    current-node has a more specific prefix than the
	//    update-node. Then the current-node should become a child
	//    of the update-node.
	// 3. The current-node does not match with the update-node,
	//    but they overlap. Then an intermediate-node sould replace
	//    the current-node with an updated prefix of the match
	//    extent between the current-node and the update-node.
	//    The current-node and the update-node become children
	//    of the intermediate node.
	//
	//    For example, given two keys, "current" and "update":
	//        current: 0b1010/4
	//        update:  0b1000/3
	//    A new key of "0b1010/2" would then be added as an
	//    intermediate key. "current" would be a child of
	//    intermediate at index "1" and "update" would be
	//    at index "0".

	// The update-node matches the current-node up to the
	// current-node's prefix, replace the current-node.
	if matchLen == currentNode.prefixLen {
		if parent == nil {
			t.root = updateNode
		} else {
			parent.children[bitVal] = updateNode
		}
		// If we're not replacing an intermediate node
		// then decrement this function's previous
		// increment of `entries`.
		if !currentNode.intermediate {
			t.entries--
		}
		updateNode.children[0] = currentNode.children[0]
		updateNode.children[1] = currentNode.children[1]
		return
	}

	// The update-node matches the current-node up to
	// the update-node's prefix, make the current-node
	// a child of the update-node.
	if matchLen == prefixLen {
		if parent == nil {
			t.root = updateNode
		} else {
			parent.children[bitVal] = updateNode
		}
		bitVal = currentNode.key.BitValueAt(matchLen)
		updateNode.children[bitVal] = currentNode
		return
	}
	// The update-node does not match the current-node
	// up to the update-node's prefix and the current-node
	// does not match the update-node up to the
	// current-node's prefix, make the nodes siblings with
	// an intermediate node.
	intermediateNode := &node[K, T]{
		prefixLen:    matchLen,
		key:          currentNode.key,
		value:        currentNode.value,
		intermediate: true,
	}
	if parent == nil {
		t.root = intermediateNode
	} else {
		parent.children[bitVal] = intermediateNode
	}
	if k.BitValueAt(matchLen) == 0 {
		intermediateNode.children[0] = updateNode
		intermediateNode.children[1] = currentNode
	} else {
		intermediateNode.children[0] = currentNode
		intermediateNode.children[1] = updateNode
	}
	return
}

// Delete deletes only keys that match the exact values of the
// prefix length and key arguments.
//
// Delete traverses the trie until it either finds a compare key
// that does not match the delete key to the compare key's prefix
// (a definitive non-match) or the compare key's prefix is equal
// to the delete prefix (a potential deletion). If the delete prefix,
// compare prefix, and match length between the keys are equal to
// the same value then the key is deleted from the trie.
//
// Note: Delete sets any prefixLen argument that exceeds the maximum
// prefix allowed by the trie to the maximum prefix allowed by the
// trie.
func (t *trie[K, T]) Delete(prefixLen uint, k Key[K]) bool {
	if k == nil {
		return false
	}
	prefixLen = min(prefixLen, t.maxPrefix)

	var (
		grandParent, parent *node[K, T]
		matchLen            uint
		bitVal, prevBitVal  uint8
	)

	currentNode := t.root
	for currentNode != nil {
		// Find to what extent the current node matches with the
		// delete-{prefix,key}.
		matchLen = t.longestPrefixMatch(currentNode, prefixLen, k)
		// The current-node does not match or it has the same
		// prefix length (the only potential deletion in the
		// trie).
		if currentNode.prefixLen != matchLen ||
			currentNode.prefixLen == prefixLen {
			break
		}
		prevBitVal = bitVal
		bitVal = k.BitValueAt(currentNode.prefixLen)
		// We preserve the grandParent in order
		// to prune intermediate nodes when they
		// are no longer necessary.
		grandParent = parent
		parent = currentNode
		currentNode = currentNode.children[bitVal]
	}
	// Not found, or the current-node does not match
	// the delete-prefix exactly, or the current-node
	// does not match the delete-{prefix,key} lookup,
	// or the current-node is intermediate.
	if currentNode == nil ||
		currentNode.prefixLen != prefixLen ||
		currentNode.prefixLen != matchLen ||
		currentNode.intermediate {
		return false
	}
	t.entries--

	// If this node has two children, we need to keep it as an intermediate
	// node because we cannot migrate both children up the trie.
	if currentNode.children[0] != nil && currentNode.children[1] != nil {
		currentNode.intermediate = true
		return true
	}

	// If the parent of the current-node to be deleted is an
	// intermediate-node and the current-node has no children
	// then the parent (intermediate) node can be deleted and
	// its other child promoted up the trie.
	if parent != nil && parent.intermediate &&
		currentNode.children[0] == nil && currentNode.children[1] == nil {
		var saveNode *node[K, T]
		if k.BitValueAt(parent.prefixLen) == 0 {
			saveNode = parent.children[1]
		} else {
			saveNode = parent.children[0]
		}
		parent.children[0] = nil
		parent.children[1] = nil
		if grandParent == nil {
			t.root = saveNode
		} else {
			grandParent.children[prevBitVal] = saveNode
		}
		return true
	}

	if currentNode.children[0] != nil {
		parent.children[bitVal] = currentNode.children[0]
	} else if currentNode.children[1] != nil {
		parent.children[bitVal] = currentNode.children[1]
	} else {
		if parent == nil {
			t.root = nil
		} else {
			parent.children[bitVal] = nil
		}
	}
	return true
}

func (t *trie[K, T]) Len() uint {
	return t.entries
}

func (t *trie[K, T]) ForEach(f ForEachFunc[Key[K], T]) {
	if t.root != nil {
		t.root.forEach(f)
	}
}

// longestPrefixMatch returns the length that the node key and
// the argument key match, with the limit of the match being
// the lesser of the node-key prefix or the argument-key prefix.
func (t *trie[K, T]) longestPrefixMatch(node *node[K, T], prefix uint, k Key[K]) uint {
	limit := min(node.prefixLen, prefix)
	prefixLen := node.key.Overlap(k.Value())
	if prefixLen >= limit {
		return limit
	}
	return prefixLen
}

func (n *node[K, T]) forEach(f ForEachFunc[Key[K], T]) {
	if !n.intermediate {
		if !f(n.prefixLen, n.key, n.value) {
			return
		}
	}
	if n.children[0] != nil {
		n.children[0].forEach(f)
	}
	if n.children[1] != nil {
		n.children[1].forEach(f)
	}
}

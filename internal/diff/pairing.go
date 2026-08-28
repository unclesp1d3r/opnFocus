package diff

import "slices"

// itemPairer matches the items of two config lists across a diff, so a change
// to one item is reported against that item rather than inferred from the list
// length.
//
// The passes run in order and each only considers what the previous ones left
// alone:
//
//  1. identity -- a stable per-item id (a UUID, a pfSense <tracker>) when the
//     vendor supplies one. Survives both reordering and edits.
//  2. content -- byte-identical items anchor in place, so only genuine edits
//     and additions are left for the final pass to consider.
//  3. similarity -- the leftovers are scored against each other and matched
//     best-first, so a deletion cannot shift an edit onto its neighbour.
//
// Whatever is unpaired at the end is a real addition or removal.
type itemPairer[T any] struct {
	// identity returns a stable id for an item, and false when it has none.
	identity func(T) (string, bool)
	// equal reports whether two items are semantically identical. It must
	// compare every meaningful field: a field it ignores produces no diff
	// entry at all, rather than a less detailed one.
	equal func(a, b T) bool
	// similarity scores how likely two items are the same item after an edit.
	similarity func(a, b T) int
	// minScore is the floor for calling a scored pair an edit rather than a
	// coincidence.
	minScore int
	// maxPairs bounds the O(n*m) similarity scoring. Above this many leftovers
	// on either side, pairing degrades to positional.
	maxPairs int
}

// pairResult records which positions found a partner.
type pairResult struct {
	oldPaired, newPaired []bool
}

// pair matches old against newItems, calling onPair for every matched
// position. Callers decide from onPair whether a pair is an edit, and read the
// result to find the additions and removals.
func (p itemPairer[T]) pair(old, newItems []T, onPair func(oi, ni int)) pairResult {
	res := pairResult{
		oldPaired: make([]bool, len(old)),
		newPaired: make([]bool, len(newItems)),
	}

	bind := func(oi, ni int) {
		res.oldPaired[oi] = true
		res.newPaired[ni] = true
		onPair(oi, ni)
	}

	p.pairByIdentity(old, newItems, &res, bind)
	p.pairByContent(old, newItems, &res, bind)
	p.pairBySimilarity(old, newItems, &res, bind)

	return res
}

// pairByIdentity matches items sharing a non-empty id. A duplicated id is not a
// usable identity and is skipped.
func (p itemPairer[T]) pairByIdentity(old, newItems []T, res *pairResult, bind func(oi, ni int)) {
	if p.identity == nil {
		return
	}

	byID := make(map[string]int, len(newItems))

	for i, item := range newItems {
		id, ok := p.identity(item)
		if !ok {
			continue
		}

		if _, seen := byID[id]; seen {
			byID[id] = -1

			continue
		}

		byID[id] = i
	}

	for oi, item := range old {
		id, ok := p.identity(item)
		if !ok {
			continue
		}

		ni, found := byID[id]
		if !found || ni < 0 || res.newPaired[ni] {
			continue
		}

		bind(oi, ni)
	}
}

// pairByContent anchors the items that did not change, so the similarity pass
// only has to reason about genuine edits.
func (p itemPairer[T]) pairByContent(old, newItems []T, res *pairResult, bind func(oi, ni int)) {
	for oi := range old {
		if res.oldPaired[oi] {
			continue
		}

		for ni := range newItems {
			if res.newPaired[ni] || !p.equal(old[oi], newItems[ni]) {
				continue
			}

			bind(oi, ni)

			break
		}
	}
}

// scoredPair is one candidate (old, new) combination and its similarity.
type scoredPair struct {
	oldIdx, newIdx, score int
}

// pairBySimilarity matches the remaining items best-first. Ties break on the
// earliest old item, then the earliest new item, so output is deterministic
// (GOTCHAS 3.1).
func (p itemPairer[T]) pairBySimilarity(old, newItems []T, res *pairResult, bind func(oi, ni int)) {
	oldLeft := unpairedIndexes(res.oldPaired)
	newLeft := unpairedIndexes(res.newPaired)

	if len(oldLeft) == 0 || len(newLeft) == 0 {
		return
	}

	if p.similarity == nil || len(oldLeft) > p.maxPairs || len(newLeft) > p.maxPairs {
		p.pairByPosition(oldLeft, newLeft, res, bind)

		return
	}

	candidates := make([]scoredPair, 0, len(oldLeft)*len(newLeft))

	for _, oi := range oldLeft {
		for _, ni := range newLeft {
			if score := p.similarity(old[oi], newItems[ni]); score >= p.minScore {
				candidates = append(candidates, scoredPair{oldIdx: oi, newIdx: ni, score: score})
			}
		}
	}

	slices.SortFunc(candidates, func(a, b scoredPair) int {
		if a.score != b.score {
			return b.score - a.score
		}

		if a.oldIdx != b.oldIdx {
			return a.oldIdx - b.oldIdx
		}

		return a.newIdx - b.newIdx
	})

	for _, c := range candidates {
		if res.oldPaired[c.oldIdx] || res.newPaired[c.newIdx] {
			continue
		}

		bind(c.oldIdx, c.newIdx)
	}
}

// pairByPosition is the fallback when similarity scoring is unavailable or the
// leftover sets are too large to score.
func (p itemPairer[T]) pairByPosition(oldLeft, newLeft []int, res *pairResult, bind func(oi, ni int)) {
	for i, oi := range oldLeft {
		if i >= len(newLeft) {
			return
		}

		if res.oldPaired[oi] || res.newPaired[newLeft[i]] {
			continue
		}

		bind(oi, newLeft[i])
	}
}

// unpairedIndexes returns the positions still awaiting a partner.
func unpairedIndexes(paired []bool) []int {
	var out []int

	for i, p := range paired {
		if !p {
			out = append(out, i)
		}
	}

	return out
}

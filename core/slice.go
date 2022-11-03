package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/consensus"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/core/vm"
	"github.com/dominant-strategies/go-quai/ethdb"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/quaiclient"
	"github.com/dominant-strategies/go-quai/trie"
	lru "github.com/hashicorp/golang-lru"
)

const (
	maxFutureHeaders        = 256
	maxPendingEtxBlocks     = 256
	maxTimeFutureHeaders    = 30
	pendingHeaderCacheLimit = 500
	pendingHeaderGCTime     = 5

	// Termini Index reference to the index of Termini struct that has the
	// previous coincident block hash
	terminiIndex = 3
)

type Slice struct {
	hc *HeaderChain

	txPool *TxPool
	miner  *Miner

	sliceDb ethdb.Database
	config  *params.ChainConfig
	engine  consensus.Engine

	quit chan struct{} // slice quit channel

	domClient  *quaiclient.Client
	domUrl     string
	subClients []*quaiclient.Client

	futureHeaders *lru.Cache
	pendingEtxs   *lru.Cache

	phCachemu sync.RWMutex

	pendingHeaderHeadHash common.Hash
	phCache               map[common.Hash]types.PendingHeader
}

func NewSlice(db ethdb.Database, config *Config, txConfig *TxPoolConfig, isLocalBlock func(block *types.Header) bool, chainConfig *params.ChainConfig, domClientUrl string, subClientUrls []string, engine consensus.Engine, cacheConfig *CacheConfig, vmConfig vm.Config, genesis *Genesis) (*Slice, error) {
	nodeCtx := common.NodeLocation.Context()
	sl := &Slice{
		config:  chainConfig,
		engine:  engine,
		sliceDb: db,
		domUrl:  domClientUrl,
		quit:    make(chan struct{}),
	}

	futureHeaders, _ := lru.New(maxFutureHeaders)
	sl.futureHeaders = futureHeaders
	pendingEtxs, _ := lru.New(maxPendingEtxBlocks)
	sl.pendingEtxs = pendingEtxs

	var err error
	sl.hc, err = NewHeaderChain(db, engine, chainConfig, cacheConfig, vmConfig)
	if err != nil {
		return nil, err
	}

	sl.txPool = NewTxPool(*txConfig, chainConfig, sl.hc)
	sl.miner = New(sl.hc, sl.txPool, config, db, chainConfig, engine, isLocalBlock)

	sl.phCache = make(map[common.Hash]types.PendingHeader)

	// only set the subClients if the chain is not Zone
	sl.subClients = make([]*quaiclient.Client, 3)
	if nodeCtx != common.ZONE_CTX {
		sl.subClients = makeSubClients(subClientUrls)
	}

	// only set domClient if the chain is not Prime.
	if nodeCtx != common.PRIME_CTX {
		go func() {
			sl.domClient = makeDomClient(domClientUrl)
		}()
	}

	if err := sl.init(genesis); err != nil {
		return nil, err
	}

	go sl.updateFutureHeaders()
	go sl.updatePendingHeadersCache()

	return sl, nil
}

// Append takes a proposed header and constructs a local block and attempts to hierarchically append it to the block graph.
// If this is called from a dominant context a domTerminus must be provided else a common.Hash{} should be used and domOrigin should be set to true.
func (sl *Slice) Append(header *types.Header, domPendingHeader *types.Header, domTerminus common.Hash, td *big.Int, domOrigin bool, reorg bool) ([]types.Transactions, error) {
	nodeCtx := common.NodeLocation.Context()
	location := header.Location()
	isCoincident := sl.engine.IsDomCoincident(header)

	// Don't append the block which already exists in the database.
	if sl.hc.HasHeader(header.Hash(), header.NumberU64()) {
		// Remove the header from the future headers cache
		sl.futureHeaders.Remove(header.Hash())

		log.Warn("Block has already been appended: ", "Hash: ", header.Hash())
		return nil, nil
	}

	// Construct the block locally
	block := sl.ConstructLocalBlock(header)
	if block == nil {
		return nil, errors.New("could not find the tx and uncle data to match the header root hash")
	}

	log.Info("Starting slice append", "hash", block.Hash(), "number", block.Header().NumberArray(), "location", block.Header().Location(), "parent hash", block.ParentHash())

	batch := sl.sliceDb.NewBatch()

	// Run Previous Coincident Reference Check (PCRC)
	domTerminus, newTermini, err := sl.pcrc(batch, block.Header(), domTerminus)
	if err != nil {
		return nil, err
	}

	// Append the new block
	err = sl.hc.Append(batch, block)
	if err != nil {
		return nil, err
	}

	if !domOrigin {
		// CalcTd on the new block
		td, err = sl.calcTd(block.Header())
		if err != nil {
			return nil, err
		}
		// HLCR
		reorg = sl.hlcr(td)
	}

	// The compute and write of the phCache is split starting here so we need to get the lock
	sl.phCachemu.Lock()
	defer sl.phCachemu.Unlock()

	// Upate the local pending header
	localPendingHeader, err := sl.miner.worker.GeneratePendingHeader(block)
	if err != nil {
		return nil, err
	}

	// Combine subordinates pending header with local pending header
	pendingHeaderWithTermini := sl.computePendingHeader(types.PendingHeader{Header: localPendingHeader, Termini: newTermini}, domPendingHeader, domOrigin)

	// Call my sub to append the block
	var newPendingEtxs []types.Transactions
	if nodeCtx != common.ZONE_CTX {
		newPendingEtxs, err = sl.subClients[location.SubIndex()].Append(context.Background(), block.Header(), pendingHeaderWithTermini.Header, domTerminus, td, true, reorg)
		if err != nil {
			return nil, err
		}
	} else {
		// If we are a zone, initialize newPendingEtxs
		newPendingEtxs = []types.Transactions{types.Transactions{}, types.Transactions{}, types.Transactions{}}
	}

	// Add our new ETXs to the newPendingEtxs collection
	// If this is a coincident block, we need to add the full rollup of ETXs.
	// Otherwise just send the new ETXs emitted in this block.
	if isCoincident {
		etxRollup, err := sl.hc.CollectEtxRollup(block)
		if err != nil {
			return nil, fmt.Errorf("unable to get ETX rollup")
		}
		newPendingEtxs[nodeCtx] = etxRollup
	} else {
		newPendingEtxs[nodeCtx] = block.ExtTransactions()
	}

	// WriteTd
	rawdb.WriteTd(batch, block.Header().Hash(), block.NumberU64(), td)

	//Append has succeeded write the batch
	if err := batch.Write(); err != nil {
		return nil, err
	}

	// Set my header chain head and generate new pending header
	err = sl.setHeaderChainHead(batch, block, reorg)
	if err != nil {
		return nil, err
	}

	sl.writeToPhCache(pendingHeaderWithTermini)
	updateMiner := sl.pickPhCacheHead(reorg, pendingHeaderWithTermini)

	// Relay the new pendingHeader
	sl.relayPh(pendingHeaderWithTermini, updateMiner, reorg, domOrigin, block.Location())

	// Remove the header from the future headers cache
	sl.futureHeaders.Remove(block.Hash())

	if domOrigin {
		go sl.procfutureHeaders()
	}

	log.Info("Appended new block", "number", block.Header().Number(), "hash", block.Hash(),
		"uncles", len(block.Uncles()), "txs", len(block.Transactions()), "gas", block.GasUsed(),
		"root", block.Root())

	return newPendingEtxs, nil
}

// relayPh sends pendingHeaderWithTermini to subordinates
func (sl *Slice) relayPh(pendingHeaderWithTermini types.PendingHeader, updateMiner bool, reorg bool, domOrigin bool, location common.Location) {
	nodeCtx := common.NodeLocation.Context()

	if nodeCtx == common.ZONE_CTX {
		if updateMiner {
			sl.phCache[sl.pendingHeaderHeadHash].Header.SetLocation(common.NodeLocation)
			sl.miner.worker.pendingHeaderFeed.Send(sl.phCache[sl.pendingHeaderHeadHash].Header)
			return
		}
	} else if !domOrigin {
		for i := range sl.subClients {
			sl.subClients[i].SubRelayPendingHeader(context.Background(), pendingHeaderWithTermini, reorg, location)
		}
	}
}

// CollectEtxsForManifest will gather the full list of ETXs that are referencable through a given manifest
func (sl *Slice) CollectSubRollups(b *types.Block) ([]types.Transactions, error) {
	nodeCtx := common.NodeLocation.Context()
	subRollups := make([]types.Transactions, 3)
	if nodeCtx < common.ZONE_CTX {
		for _, hash := range b.SubManifest() {
			var pendingEtxs []types.Transactions
			// Look for pending ETXs first in pending ETX cache, then in database
			if res, ok := sl.pendingEtxs.Get(hash); ok && res != nil {
				pendingEtxs = res.([]types.Transactions)
			} else if res := rawdb.ReadPendingEtxs(sl.sliceDb, hash); res != nil {
				pendingEtxs = res
			} else {
				return nil, fmt.Errorf("unable to find pending etxs for hash in manifest, hash: %s", hash.String())
			}
			for ctx := nodeCtx; ctx < common.HierarchyDepth; ctx++ {
				subRollups[ctx] = append(subRollups[ctx], pendingEtxs[ctx]...)
			}
		}
		if subRollupHash := types.DeriveSha(subRollups[nodeCtx+1], trie.NewStackTrie(nil)); subRollupHash != b.EtxRollupHash(nodeCtx+1) {
			return nil, errors.New("sub rollup does not match sub rollup hash")
		}
	}
	return subRollups, nil
}

// setHeaderChainHead updates the current chain head and returns a new pending header
func (sl *Slice) setHeaderChainHead(batch ethdb.Batch, block *types.Block, reorg bool) error {
	// If reorg is true set to newly appended block
	if reorg {
		err := sl.hc.SetCurrentHeader(block.Header())
		if err != nil {
			return err
		}
		sl.hc.chainHeadFeed.Send(ChainHeadEvent{Block: block})
	} else {
		sl.hc.chainSideFeed.Send(ChainSideEvent{Block: block})
	}

	return nil
}

// PCRC previous coincidence reference check makes sure there are not any cyclic references in the graph and calculates new termini and the block terminus
func (sl *Slice) pcrc(batch ethdb.Batch, header *types.Header, domTerminus common.Hash) (common.Hash, []common.Hash, error) {
	nodeCtx := common.NodeLocation.Context()
	location := header.Location()

	isDomCoincident := sl.engine.IsDomCoincident(header)

	log.Debug("PCRC:", "Parent Hash:", header.ParentHash(), "Number", header.Number, "Location:", header.Location())
	termini := sl.hc.GetTerminiByHash(header.ParentHash())

	if len(termini) != 4 {
		return common.Hash{}, []common.Hash{}, errors.New("length of termini not equal to 4")
	}

	newTermini := make([]common.Hash, len(termini))
	for i, terminus := range termini {
		newTermini[i] = terminus
	}

	// Genesis escape for the domTerminus
	if header.ParentHash(common.PRIME_CTX) == sl.config.GenesisHash {
		domTerminus = sl.config.GenesisHash
	}

	// Set the subtermini
	if nodeCtx != common.ZONE_CTX {
		newTermini[location.SubIndex()] = header.Hash()
	}

	// Set the terminus
	if nodeCtx == common.PRIME_CTX || isDomCoincident {
		newTermini[terminiIndex] = header.Hash()
	} else {
		newTermini[terminiIndex] = termini[terminiIndex]
	}

	// Check for a graph cyclic reference
	if isDomCoincident {
		if termini[terminiIndex] != domTerminus {
			log.Warn("Cyclic Block:", "block number", header.NumberArray(), "hash", header.Hash(), "terminus", domTerminus, "termini", termini)
			return common.Hash{}, []common.Hash{}, errors.New("termini do not match, block rejected due to cyclic reference")
		}
	}

	//Save the termini
	rawdb.WriteTermini(batch, header.Hash(), newTermini)

	if nodeCtx == common.ZONE_CTX {
		return common.Hash{}, newTermini, nil
	}

	return termini[location.SubIndex()], newTermini, nil
}

// HLCR Hierarchical Longest Chain Rule compares externTd to the currentHead Td and returns true if externTd is greater
func (sl *Slice) hlcr(externTd *big.Int) bool {
	currentTd := sl.hc.GetTdByHash(sl.hc.CurrentHeader().Hash())
	log.Debug("HLCR:", "Header hash:", sl.hc.CurrentHeader().Hash(), "currentTd:", currentTd, "externTd:", externTd)
	reorg := currentTd.Cmp(externTd) < 0
	//TODO need to handle the equal td case
	// https://github.com/dominant-strategies/go-quai/issues/430
	return reorg
}

// CalcTd calculates the TD of the given header using PCRC.
func (sl *Slice) calcTd(header *types.Header) (*big.Int, error) {
	// Stop from
	isDomCoincident := sl.engine.IsDomCoincident(header)
	if isDomCoincident {
		return nil, errors.New("td on a dom block cannot be calculated by a sub")
	}
	priorTd := sl.hc.GetTd(header.ParentHash(), header.NumberU64()-1)
	if priorTd == nil {
		return nil, consensus.ErrFutureBlock
	}
	Td := priorTd.Add(priorTd, header.Difficulty())
	return Td, nil
}

// GetPendingHeader is used by the miner to request the current pending header
func (sl *Slice) GetPendingHeader() (*types.Header, error) {
	if ph := sl.phCache[sl.pendingHeaderHeadHash].Header; ph != nil {
		return ph, nil
	} else {
		return nil, errors.New("empty pending header")
	}
}

// GetManifest gathers the manifest of ancestor block hashes since the last
// coincident block.
func (sl *Slice) GetManifest(blockHash common.Hash) (types.BlockManifest, error) {
	header := sl.hc.GetHeaderByHash(blockHash)
	if header == nil {
		return nil, errors.New("block not found")
	}
	return sl.hc.CollectBlockManifest(header)
}

// GetSubManifest gets the block manifest from the subordinate node which
// produced this block
func (sl *Slice) GetSubManifest(slice common.Location, blockHash common.Hash) (types.BlockManifest, error) {
	subIdx := slice.SubIndex()
	return sl.subClients[subIdx].GetManifest(context.Background(), blockHash)
}

func (sl *Slice) AddPendingEtxs(pEtxs types.PendingEtxs) error {
	log.Info("Received pending ETXs", "block: ", pEtxs.Header.Hash())
	// Only write the pending ETXs if we have not seen them before
	if !sl.pendingEtxs.Contains(pEtxs.Header.Hash()) {
		// Write to pending ETX database
		rawdb.WritePendingEtxs(sl.sliceDb, pEtxs.Header.Hash(), pEtxs.Etxs)
		// Also write to cache for faster access
		sl.pendingEtxs.Add(pEtxs.Header.Hash(), pEtxs.Etxs)
	}
	return nil
}

// SendPendingEtxsToDom shares a set of pending ETXs with your dom, so he can reference them when a coincident block is found
func (sl *Slice) SendPendingEtxsToDom(pEtxs types.PendingEtxs) error {
	return sl.domClient.SendPendingEtxsToDom(context.Background(), pEtxs)
}

// SubRelayPendingHeader takes a pending header from the sender (ie dominant), updates the phCache with a composited header and relays result to subordinates
func (sl *Slice) SubRelayPendingHeader(pendingHeader types.PendingHeader, reorg bool, location common.Location) {
	sl.phCachemu.Lock()
	defer sl.phCachemu.Unlock()
	nodeCtx := common.NodeLocation.Context()

	if nodeCtx == common.REGION_CTX {
		// Adding a guard on the region that was already updated in the synchronous path.
		if location.Region() != common.NodeLocation.Region() {
			err := sl.updatePhCacheFromDom(pendingHeader, common.NodeLocation.Region(), []int{common.PRIME_CTX}, reorg)
			if err != nil {
				return
			}
		}
		for i := range sl.subClients {
			sl.subClients[i].SubRelayPendingHeader(context.Background(), sl.phCache[pendingHeader.Termini[common.NodeLocation.Region()]], reorg, location)
		}
	} else {
		// This check prevents a double send to the miner.
		// If the previous block on which the given pendingHeader was built is the same as the NodeLocation
		// the pendingHeader update has already been sent to the miner for the given location in relayPh.
		if !location.Equal(common.NodeLocation) {
			err := sl.updatePhCacheFromDom(pendingHeader, common.NodeLocation.Zone(), []int{common.PRIME_CTX, common.REGION_CTX}, reorg)
			if err != nil {
				return
			}
			bestPh, exists := sl.phCache[sl.pendingHeaderHeadHash]
			if exists {
				sl.miner.worker.pendingHeaderFeed.Send(bestPh.Header)
			}
		}
	}
}

// computePendingHeader takes in an localPendingHeaderWithTermini and updates the pending header on the same terminus if the number is greater
func (sl *Slice) computePendingHeader(localPendingHeaderWithTermini types.PendingHeader, domPendingHeader *types.Header, domOrigin bool) types.PendingHeader {
	nodeCtx := common.NodeLocation.Context()

	var cachedPendingHeaderWithTermini types.PendingHeader
	hash := localPendingHeaderWithTermini.Termini[terminiIndex]
	cachedPendingHeaderWithTermini, exists := sl.phCache[hash]
	var newPh *types.Header

	if exists {
		newPh = sl.combinePendingHeader(localPendingHeaderWithTermini.Header, cachedPendingHeaderWithTermini.Header, nodeCtx)
		return types.PendingHeader{Header: newPh, Termini: localPendingHeaderWithTermini.Termini}
	} else {
		if domOrigin {
			newPh = sl.combinePendingHeader(localPendingHeaderWithTermini.Header, domPendingHeader, nodeCtx)
			return types.PendingHeader{Header: newPh, Termini: localPendingHeaderWithTermini.Termini}
		}
		return localPendingHeaderWithTermini
	}
}

// updatePhCacheFromDom combines the recieved pending header with the pending header stored locally at a given terminus for specified context
func (sl *Slice) updatePhCacheFromDom(pendingHeader types.PendingHeader, terminiIndex int, indices []int, reorg bool) error {

	var localPendingHeader types.PendingHeader
	hash := pendingHeader.Termini[terminiIndex]
	localPendingHeader, exists := sl.phCache[hash]

	if exists {
		for _, i := range indices {
			localPendingHeader.Header = sl.combinePendingHeader(pendingHeader.Header, localPendingHeader.Header, i)
		}
		localPendingHeader.Header.SetLocation(common.NodeLocation)
		sl.phCache[hash] = localPendingHeader

		if reorg {
			sl.pendingHeaderHeadHash = hash
		}
		return nil
	}
	log.Warn("no pending header found for", "terminus", hash)
	return errors.New("no pending header found in cache")
}

// writePhCache dom writes a given pendingHeaderWithTermini to the cache with the terminus used as the key.
func (sl *Slice) writeToPhCache(pendingHeaderWithTermini types.PendingHeader) {
	sl.phCache[pendingHeaderWithTermini.Termini[terminiIndex]] = pendingHeaderWithTermini
}

// pickPhCacheHead determines if the provided pendingHeader should be selected and returns true if selected
func (sl *Slice) pickPhCacheHead(reorg bool, externPendingHeaderWithTermini types.PendingHeader) bool {
	if reorg {
		sl.pendingHeaderHeadHash = externPendingHeaderWithTermini.Termini[terminiIndex]
		return true
	}

	localPendingHeader, exists := sl.phCache[externPendingHeaderWithTermini.Termini[terminiIndex]]
	if exists && (externPendingHeaderWithTermini.Header.NumberU64() > localPendingHeader.Header.NumberU64()) {
		sl.updateCurrentPendingHeader(externPendingHeaderWithTermini)
		return true
	}
	return false
}

// updateCurrentPendingHeader compares the externPh parent td to the sl.pendingHeader parent td and sets sl.pendingHeader to the exterPh if the td is greater
func (sl *Slice) updateCurrentPendingHeader(externPendingHeader types.PendingHeader) {
	externTd := sl.hc.GetTdByHash(externPendingHeader.Header.ParentHash())
	currentTd := sl.hc.GetTdByHash(sl.phCache[sl.pendingHeaderHeadHash].Header.ParentHash())
	log.Debug("updateCurrentPendingHeader:", "currentParent:", sl.phCache[sl.pendingHeaderHeadHash].Header.ParentHash(), "currentTd:", currentTd, "externParent:", externPendingHeader.Header.ParentHash(), "externTd:", externTd)
	if currentTd.Cmp(externTd) < 0 {
		sl.pendingHeaderHeadHash = externPendingHeader.Termini[terminiIndex]
	}
}

// init checks if the headerchain is empty and if it's empty appends the Knot
// otherwise loads the last stored state of the chain.
func (sl *Slice) init(genesis *Genesis) error {
	nodeCtx := common.NodeLocation.Context()
	// Even though the genesis block cannot have any ETXs, we still need an empty
	// pending ETX entry for that block hash, so that the state processor can build
	// on it
	genesisHash := sl.Config().GenesisHash
	genesisHeader := sl.hc.GetHeader(genesisHash, 0)
	if genesisHeader == nil {
		return errors.New("failed to get genesis header")
	}
	emptyPendingEtxs := []types.Transactions{types.Transactions{}, types.Transactions{}, types.Transactions{}}
	err := sl.AddPendingEtxs(types.PendingEtxs{genesisHeader, emptyPendingEtxs})
	if err != nil {
		return err
	}
	// If the headerchain is empty start from genesis
	if sl.hc.Empty() {
		// Initialize slice state for genesis knot
		genesisTermini := []common.Hash{genesisHash, genesisHash, genesisHash, genesisHash}
		sl.pendingHeaderHeadHash = genesisHash
		rawdb.WriteTermini(sl.sliceDb, genesisHash, genesisTermini)

		// Append each of the knot blocks

		knot := genesis.Knot[:]
		for _, block := range knot {
			if block != nil {
				location := block.Header().Location()
				if nodeCtx == common.PRIME_CTX {
					rawdb.WritePendingBlockBody(sl.sliceDb, block.Root(), block.Body())
					_, err := sl.Append(block.Header(), types.EmptyHeader(), genesisHash, block.Difficulty(), false, false)
					if err != nil {
						log.Warn("Failed to append block", "hash:", block.Hash(), "Number:", block.Number(), "Location:", block.Header().Location(), "error:", err)
					}
				} else if location.Region() == common.NodeLocation.Region() && len(common.NodeLocation) == common.REGION_CTX {
					rawdb.WritePendingBlockBody(sl.sliceDb, block.Root(), block.Body())
				} else if bytes.Equal(location, common.NodeLocation) {
					rawdb.WritePendingBlockBody(sl.sliceDb, block.Root(), block.Body())
				}
			}
		}
	} else { // load the phCache and slice current pending header hash
		if err := sl.loadLastState(); err != nil {
			return err
		}
	}
	return nil
}

// gcPendingHeader goes through the phCache and deletes entries older than the pendingHeaderCacheLimit
func (sl *Slice) gcPendingHeaders() {
	sl.phCachemu.Lock()
	defer sl.phCachemu.Unlock()
	for hash, pendingHeader := range sl.phCache {
		if pendingHeader.Header.NumberU64()+pendingHeaderCacheLimit < sl.hc.CurrentHeader().NumberU64() {
			delete(sl.phCache, hash)
		}
	}
}

// constructLocalBlock takes a header and construct the Block locally
func (sl *Slice) ConstructLocalBlock(header *types.Header) *types.Block {
	var block *types.Block
	// check if the header has empty uncle and tx root
	if header.EmptyBody() {
		// construct block with empty transactions and uncles
		block = types.NewBlockWithHeader(header)
	} else {
		pendingBlockBody := sl.PendingBlockBody(header.Root())
		if pendingBlockBody != nil {
			// Load uncles because they are not included in the block response.
			txs := make([]*types.Transaction, len(pendingBlockBody.Transactions))
			for i, tx := range pendingBlockBody.Transactions {
				txs[i] = tx
			}

			uncles := make([]*types.Header, len(pendingBlockBody.Uncles))
			for i, uncle := range pendingBlockBody.Uncles {
				uncles[i] = uncle
				log.Debug("Pending Block uncle", "hash: ", uncle.Hash())
			}

			etxs := make([]*types.Transaction, len(pendingBlockBody.ExtTransactions))
			for i, etx := range pendingBlockBody.ExtTransactions {
				etxs[i] = etx
			}

			subBlockHashes := make(types.BlockManifest, len(pendingBlockBody.SubManifest))
			for i, blockHash := range pendingBlockBody.SubManifest {
				subBlockHashes[i] = blockHash
			}

			block = types.NewBlockWithHeader(header).WithBody(txs, uncles, etxs, subBlockHashes)
		}
	}
	return block
}

// combinePendingHeader updates the pending header at the given index with the value from given header.
func (sl *Slice) combinePendingHeader(header *types.Header, slPendingHeader *types.Header, index int) *types.Header {
	// copying the slPendingHeader and updating the copy to remove any shared memory access issues
	combinedPendingHeader := types.CopyHeader(slPendingHeader)

	combinedPendingHeader.SetParentHash(header.ParentHash(index), index)
	combinedPendingHeader.SetUncleHash(header.UncleHash(index), index)
	combinedPendingHeader.SetNumber(header.Number(index), index)
	combinedPendingHeader.SetExtra(header.Extra())
	combinedPendingHeader.SetBaseFee(header.BaseFee(index), index)
	combinedPendingHeader.SetGasLimit(header.GasLimit(index), index)
	combinedPendingHeader.SetGasUsed(header.GasUsed(index), index)
	combinedPendingHeader.SetTxHash(header.TxHash(index), index)
	combinedPendingHeader.SetEtxHash(header.EtxHash(index), index)
	combinedPendingHeader.SetEtxRollupHash(header.EtxRollupHash(index), index)
	combinedPendingHeader.SetManifestHash(header.ManifestHash(index), index)
	combinedPendingHeader.SetReceiptHash(header.ReceiptHash(index), index)
	combinedPendingHeader.SetRoot(header.Root(index), index)
	combinedPendingHeader.SetDifficulty(header.Difficulty(index), index)
	combinedPendingHeader.SetCoinbase(header.Coinbase(index), index)
	combinedPendingHeader.SetBloom(header.Bloom(index), index)

	return combinedPendingHeader
}

// MakeDomClient creates the quaiclient for the given domurl
func makeDomClient(domurl string) *quaiclient.Client {
	if domurl == "" {
		log.Crit("dom client url is empty")
	}
	domClient, err := quaiclient.Dial(domurl)
	if err != nil {
		log.Crit("Error connecting to the dominant go-quai client", "err", err)
	}
	return domClient
}

// MakeSubClients creates the quaiclient for the given suburls
func makeSubClients(suburls []string) []*quaiclient.Client {
	subClients := make([]*quaiclient.Client, 3)
	for i, suburl := range suburls {
		if suburl == "" {
			log.Warn("sub client url is empty")
		}
		subClient, err := quaiclient.Dial(suburl)
		if err != nil {
			log.Crit("Error connecting to the subordinate go-quai client for index", "index", i, " err ", err)
		}
		subClients[i] = subClient
	}
	return subClients
}

// procfutureHeaders sorts the future block cache and attempts to append
func (sl *Slice) procfutureHeaders() {
	headers := make([]*types.Header, 0, sl.futureHeaders.Len())
	for _, hash := range sl.futureHeaders.Keys() {
		if header, exist := sl.futureHeaders.Peek(hash); exist {
			headers = append(headers, header.(*types.Header))
		}
	}
	if len(headers) > 0 {
		sort.Slice(headers, func(i, j int) bool {
			return headers[i].NumberU64() < headers[j].NumberU64()
		})

		for _, head := range headers {
			var nilHash common.Hash
			_, err := sl.Append(head, types.EmptyHeader(), nilHash, big.NewInt(0), false, false)
			if err != nil {
				if err.Error() != "sub not synced to dom" {
					// Remove the header from the future headers cache
					sl.futureHeaders.Remove(head.Hash())
				}
			}
		}
	}
}

// addfutureHeader adds a block to the future block cache
func (sl *Slice) addfutureHeader(header *types.Header) error {
	max := uint64(time.Now().Unix() + maxTimeFutureHeaders)
	if header.Time() > max {
		return fmt.Errorf("future block timestamp %v > allowed %v", header.Time(), max)
	}
	if !sl.futureHeaders.Contains(header.Hash()) {
		sl.futureHeaders.Add(header.Hash(), header)
	}
	return nil
}

// updatefutureHeaders is a time to procfutureHeaders
func (sl *Slice) updateFutureHeaders() {
	futureTimer := time.NewTicker(3 * time.Second)
	defer futureTimer.Stop()
	for {
		select {
		case <-futureTimer.C:
			sl.procfutureHeaders()
		case <-sl.quit:
			return
		}
	}
}

// updatePendingheadersCache is a timer to gcPendingHeaders
func (sl *Slice) updatePendingHeadersCache() {
	futureTimer := time.NewTicker(pendingHeaderGCTime * time.Minute)
	defer futureTimer.Stop()
	for {
		select {
		case <-futureTimer.C:
			sl.gcPendingHeaders()
		case <-sl.quit:
			return
		}
	}
}

// loadLastState loads the phCache and the slice pending header hash from the db.
func (sl *Slice) loadLastState() error {
	sl.phCache = rawdb.ReadPhCache(sl.sliceDb)
	sl.pendingHeaderHeadHash = rawdb.ReadCurrentPendingHeaderHash(sl.sliceDb)
	return nil
}

// Stop stores the phCache and the sl.pendingHeader hash value to the db.
func (sl *Slice) Stop() {
	// write the ph head hash to the db.
	rawdb.WriteCurrentPendingHeaderHash(sl.sliceDb, sl.pendingHeaderHeadHash)
	// Write the ph cache to the dd.
	rawdb.WritePhCache(sl.sliceDb, sl.phCache)

	close(sl.quit)

	sl.hc.Stop()
	sl.txPool.Stop()
	sl.miner.Stop()
}

func (sl *Slice) Config() *params.ChainConfig { return sl.config }

func (sl *Slice) Engine() consensus.Engine { return sl.engine }

func (sl *Slice) HeaderChain() *HeaderChain { return sl.hc }

func (sl *Slice) TxPool() *TxPool { return sl.txPool }

func (sl *Slice) Miner() *Miner { return sl.miner }

func (sl *Slice) PendingBlockBody(hash common.Hash) *types.Body {
	return rawdb.ReadPendingBlockBody(sl.sliceDb, hash)
}
